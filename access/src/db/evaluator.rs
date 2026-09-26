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
                .order_by_asc(rule::Column::Id)
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
#[path = "../../tests/unit/evaluator.rs"]
mod tests;
