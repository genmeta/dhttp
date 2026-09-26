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

async fn seeded_store() -> (
    TestHome,
    sea_orm::DatabaseConnection,
    identity::Name<'static>,
) {
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
async fn reappending_rule_makes_it_highest_priority() {
    let test_home = TestHome::new("reappend-priority");
    let home = test_home.home();
    let identity: identity::Name<'static> = "server.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .expect("init access db");
    let service = LocationService::new(&db);
    let location = "/".parse().unwrap();
    let alice_expr: crate::expr::exprs::LocationRuleExprs = "alice.pilot~".parse().unwrap();

    let first_allow = service
        .append_rule_with_id(&location, RequestAction::Allow, alice_expr.clone())
        .await
        .expect("allow alice");
    service
        .append_rule(&location, RequestAction::Deny, "*?".parse().unwrap())
        .await
        .expect("deny named clients");
    let refreshed_allow = service
        .append_rule_with_id(&location, RequestAction::Allow, alice_expr)
        .await
        .expect("reappend alice allow");

    assert_eq!(refreshed_allow.id, first_allow.id);
    let database = LocationRulesDatabase::new(db);
    assert_eq!(
        database
            .evaluate("/", &TestRequest::named("alice.pilot.dhttp.net"))
            .await
            .expect("latest matching rule should decide")
            .action,
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
