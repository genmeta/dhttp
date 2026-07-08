use std::collections::BTreeMap;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{
    db::entities::location::{location, rule},
    expr::{eval::Evaluable, rule::Rule},
    matcher::PatternWithTime,
    pattern::LocationPatternKind,
    policy::{
        LocationRuleDecision, LocationRuleDecisionError, LocationRuleEvaluator, LocationRuleFuture,
        LocationRuleRequest,
    },
};

#[derive(Debug, Clone)]
pub struct LocationRulesDatabase {
    db: sea_orm::DatabaseConnection,
}

impl LocationRulesDatabase {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }
}

impl LocationRuleEvaluator for LocationRulesDatabase {
    fn evaluate<'a>(
        &'a self,
        path: &'a str,
        request: &'a (dyn LocationRuleRequest + Send + Sync),
    ) -> LocationRuleFuture<'a> {
        Box::pin(async move {
            let locations = location::Entity::find()
                .all(&self.db)
                .await
                .map_err(LocationRuleDecisionError::backend)?;

            #[allow(clippy::mutable_key_type)]
            let ordered_locations: BTreeMap<PatternWithTime<LocationPatternKind>, i32> = locations
                .into_iter()
                .map(|location| {
                    (
                        PatternWithTime::new(
                            location.created_at.timestamp_micros(),
                            location.pattern,
                        ),
                        location.id,
                    )
                })
                .collect();

            let Some((location_pattern, location_id)) = ordered_locations
                .iter()
                .find(|(location_pattern, _)| location_pattern.pattern().is_match(path))
                .map(|(location_pattern, location_id)| {
                    (location_pattern.pattern().clone(), *location_id)
                })
            else {
                return Err(LocationRuleDecisionError::NoRuleSet {
                    path: path.to_owned(),
                });
            };

            let rules = rule::Entity::find()
                .filter(rule::Column::LocationId.eq(location_id))
                .order_by_asc(rule::Column::CreatedAt)
                .all(&self.db)
                .await
                .map_err(LocationRuleDecisionError::backend)?;

            for rule::Model { action, exprs, .. } in rules.into_iter().rev() {
                let evaluated = Rule::new(exprs.polish(), action).eval(request);
                if let Some(action) = evaluated {
                    return Ok(LocationRuleDecision {
                        location: location_pattern,
                        action,
                    });
                }
            }

            Err(LocationRuleDecisionError::NoRuleInSet {
                location: location_pattern,
            })
        })
    }
}

#[cfg(all(test, feature = "migration"))]
mod tests {
    use std::path::PathBuf;

    use crate::{
        action::RequestAction,
        db::{
            evaluator::LocationRulesDatabase, identity, init_identity_access_database,
            service::location_service::LocationService,
        },
        expr::{atomics::AtomicLocationRuleExpr, atomics::EvalError, eval::Evaluable},
        matcher::LocationRulesMatcher,
        policy::{LocationRuleDecisionError, LocationRuleEvaluator, LocationRuleRequest},
    };

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "dhttp-access-db-evaluator-{name}-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).expect("create test home");
            Self { path }
        }

        fn home(&self) -> crate::db::DhttpHome {
            crate::db::DhttpHome::new(self.path.clone())
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct TestRequest {
        client_name: Option<String>,
    }

    impl TestRequest {
        fn named(name: &str) -> Self {
            Self {
                client_name: Some(name.to_owned()),
            }
        }
    }

    impl LocationRuleRequest for TestRequest {
        fn eval_atomic(&self, expr: &AtomicLocationRuleExpr) -> Result<bool, EvalError> {
            Ok(match expr {
                AtomicLocationRuleExpr::Any(..) => true,
                AtomicLocationRuleExpr::ClientName(pattern) => {
                    pattern.eval(&self.client_name.as_deref())?
                }
                AtomicLocationRuleExpr::Method(_) => false,
                AtomicLocationRuleExpr::Header(_) => false,
                AtomicLocationRuleExpr::Query(_) => false,
            })
        }
    }

    async fn seeded_store() -> (TestHome, sea_orm::DatabaseConnection, identity::Name<'static>) {
        let test_home = TestHome::new("seeded");
        let home = test_home.home();
        let identity: identity::Name<'static> = "server.pilot".parse().unwrap();
        let db = init_identity_access_database(&home, identity.borrow())
            .await
            .expect("init access db");
        let service = LocationService::new(&db);
        service
            .append_rule(
                &"/".parse().unwrap(),
                RequestAction::Allow,
                "*".parse().unwrap(),
            )
            .await
            .expect("allow root");
        service
            .append_rule(
                &"/files".parse().unwrap(),
                RequestAction::Deny,
                "*?".parse().unwrap(),
            )
            .await
            .expect("deny named clients on files");
        service
            .append_rule(
                &"/files".parse().unwrap(),
                RequestAction::Allow,
                "alice.pilot~".parse().unwrap(),
            )
            .await
            .expect("allow alice on files");
        (test_home, db, identity)
    }

    #[tokio::test]
    async fn database_evaluator_matches_memory_matcher_decisions() {
        let (_home, db, _identity) = seeded_store().await;
        let service = LocationService::new(&db);
        let matcher = LocationRulesMatcher::from(
            service
                .list_all_rules()
                .await
                .expect("list all rules for matcher"),
        );
        let database = LocationRulesDatabase::new(db.clone());
        let alice = TestRequest::named("alice.pilot.dhttp.net");
        let bob = TestRequest::named("bob.pilot.dhttp.net");

        for (path, request) in [("/", &bob), ("/files", &alice), ("/files", &bob)] {
            let memory = matcher
                .evaluate(path, request)
                .await
                .expect("memory matcher should decide");
            let live = database
                .evaluate(path, request)
                .await
                .expect("database evaluator should decide");
            assert_eq!(
                (memory.location.to_string(), memory.action),
                (live.location.to_string(), live.action),
                "memory and DB decisions differ for {path}"
            );
        }
    }

    #[tokio::test]
    async fn database_evaluator_reads_committed_rule_changes() {
        let (_home, db, _identity) = seeded_store().await;
        let service = LocationService::new(&db);
        let stale_matcher = LocationRulesMatcher::from(
            service
                .list_all_rules()
                .await
                .expect("list all rules for stale matcher"),
        );
        let database = LocationRulesDatabase::new(db.clone());
        let bob = TestRequest::named("bob.pilot.dhttp.net");

        assert_eq!(
            database.evaluate("/", &bob).await.unwrap().action,
            RequestAction::Allow
        );

        service
            .remove_rule_set(&"/".parse().unwrap())
            .await
            .expect("clear root rules");
        service
            .append_rule(
                &"/".parse().unwrap(),
                RequestAction::Deny,
                "*?".parse().unwrap(),
            )
            .await
            .expect("deny root");

        assert_eq!(
            database.evaluate("/", &bob).await.unwrap().action,
            RequestAction::Deny
        );
        assert_eq!(
            stale_matcher.evaluate("/", &bob).await.unwrap().action,
            RequestAction::Allow
        );
    }

    #[tokio::test]
    async fn database_evaluator_reports_no_rule_set() {
        let test_home = TestHome::new("empty");
        let home = test_home.home();
        let identity: identity::Name<'static> = "server.pilot".parse().unwrap();
        let db = init_identity_access_database(&home, identity.borrow())
            .await
            .expect("init access db");
        let database = LocationRulesDatabase::new(db);
        let bob = TestRequest::named("bob.pilot.dhttp.net");

        let error = database
            .evaluate("/missing", &bob)
            .await
            .expect_err("empty DB should not match");

        assert!(matches!(error, LocationRuleDecisionError::NoRuleSet { .. }));
    }
}
