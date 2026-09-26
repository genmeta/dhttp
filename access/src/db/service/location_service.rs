use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use crate::{
    action::RequestAction,
    error::location::*,
    expr::exprs::LocationRuleExprs,
    matcher::{LocationPatternMatcher, LocationRulesMatcher, PatternWithTime},
    pattern::{LocationPattern, LocationPatternKind},
};
use sea_orm::{prelude::*, sea_query::OnConflict, *};
use snafu::{OptionExt, ResultExt};

use crate::db::{entities::location::*, service::error::*};

pub struct LocationService<'db> {
    db: &'db DatabaseConnection,
}

impl LocationService<'_> {
    pub fn new(db: &DatabaseConnection) -> LocationService<'_> {
        LocationService { db }
    }
}

pub struct RuleSets(pub Vec<location::Model>);

impl Display for RuleSets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(rule_sets) = self;
        for location::Model { pattern, .. } in rule_sets {
            writeln!(f, "- {pattern}")?;
        }
        Ok(())
    }
}

type LocationRuleSetMap =
    BTreeMap<PatternWithTime<LocationPatternKind>, (location::Model, Vec<rule::Model>)>;

pub struct MatchedLocationRules {
    pub location: LocationPattern,
    pub rules: Vec<rule::Model>,
}

fn deduplicate_rules(rules: &mut Vec<rule::Model>) {
    let mut unique = Vec::with_capacity(rules.len());
    for candidate in rules.drain(..) {
        let duplicate = unique
            .iter()
            .any(|existing: &rule::Model| same_logical_rule(existing, &candidate));
        if !duplicate {
            unique.push(candidate);
        }
    }
    *rules = unique;
}

fn same_logical_rule(left: &rule::Model, right: &rule::Model) -> bool {
    left.action == right.action && left.exprs.polish() == right.exprs.polish()
}

impl Display for MatchedLocationRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { location, rules } = self;
        writeln!(f, "- {location}")?;
        for (i, rule::Model { action, exprs, .. }) in rules.iter().enumerate() {
            writeln!(f, "  #{i}: {action} {exprs}")?;
        }
        Ok(())
    }
}

pub struct AllLocationRules {
    pub map: LocationRuleSetMap,
}

impl From<AllLocationRules> for LocationRulesMatcher {
    fn from(AllLocationRules { map }: AllLocationRules) -> Self {
        use crate::db::entities::location::*;
        #[allow(clippy::mutable_key_type)]
        Self {
            map: map
                .into_iter()
                .map(|(location_pattern, (.., rules))| {
                    let rules = rules
                        .into_iter()
                        .map(|rule::Model { exprs, action, .. }| (exprs, action))
                        .collect();
                    (location_pattern, rules)
                })
                .collect(),
        }
    }
}

impl Display for AllLocationRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (location_pattern, (_location_model, rules)) in &self.map {
            writeln!(f, "- {location_pattern}")?;
            for (i, rule::Model { action, exprs, .. }) in rules.iter().enumerate() {
                writeln!(f, "  #{i}: {action} {exprs}")?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

#[derive(snafu::Snafu, Debug)]
pub enum RemoveRuleFailed {
    #[snafu(display("rule `{seq}` does not exist"))]
    RuleNotExist { seq: usize },
    #[snafu(display("rule set does not exist"))]
    RuleSetNotExist { source: LocateLocationFailed },
}

#[derive(snafu::Snafu, Debug)]
pub enum RemoveRuleByIdFailed {
    #[snafu(display("rule `{id}` does not exist"))]
    RemoveRuleIdNotExist { id: i32 },
    #[snafu(display("rule set does not exist"))]
    RemoveRuleSetByIdNotExist { source: LocateLocationFailed },
}

#[derive(snafu::Snafu, Debug)]
pub enum ReplaceRuleByIdFailed {
    #[snafu(display("rule `{id}` does not exist"))]
    ReplaceRuleIdNotExist { id: i32 },
    #[snafu(display("rule set does not exist"))]
    ReplaceRuleSetByIdNotExist { source: LocateLocationFailed },
}

include!("location_service/read.rs");
include!("location_service/remove.rs");
include!("location_service/write.rs");
