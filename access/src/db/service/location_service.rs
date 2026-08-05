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
use sea_orm::{prelude::*, *};
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
        let duplicate = unique.iter().any(|existing: &rule::Model| {
            existing.action == candidate.action
                && existing.exprs.polish() == candidate.exprs.polish()
        });
        if !duplicate {
            unique.push(candidate);
        }
    }
    *rules = unique;
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

impl LocationService<'_> {
    pub async fn ensure_store(&self) -> Result<(), EnsureStoreError> {
        location::Entity::find()
            .limit(1)
            .all(self.db)
            .await
            .context(ensure_store_error::QueryStoreSnafu)?;
        Ok(())
    }

    pub async fn list_rule_sets(&self) -> Result<RuleSets, ListRuleSetsError> {
        let rule_sets = location::Entity::find()
            .order_by_asc(location::Column::Pattern)
            .all(self.db)
            .await
            .context(list_rule_sets_error::QueryRuleSetsSnafu)?;

        Ok(RuleSets(rule_sets))
    }

    async fn match_location_internal(
        txn: &DatabaseTransaction,
        location: &LocationPattern,
        strict: bool,
    ) -> Result<Option<(i32, LocationPattern)>, MatchLocationError> {
        let strict_matched: Option<(i32, LocationPattern)> = location::Entity::find()
            .filter(location::Column::Pattern.eq(location.clone()))
            .select_only()
            .columns([location::Column::Id, location::Column::Pattern])
            .into_tuple()
            .one(txn)
            .await
            .context(match_location_error::QueryExactLocationSnafu)?;

        let (matched_location_id, matched_pattern) = match strict_matched {
            Some(tuple) => tuple,
            None if strict => return Ok(None),
            None => {
                let locations: Vec<(LocationPattern, i32)> = location::Entity::find()
                    .select_only()
                    .columns([location::Column::Pattern, location::Column::Id])
                    .into_tuple()
                    .all(txn)
                    .await
                    .context(match_location_error::QueryLocationsSnafu)?;

                let pattern_set = LocationPatternMatcher::from_iter(locations);
                let Some((match_location_id, matched_pattern, _)) =
                    pattern_set.r#match(&location.to_string())
                else {
                    return Ok(None);
                };
                (*match_location_id, matched_pattern.clone())
            }
        };

        Ok(Some((matched_location_id, matched_pattern)))
    }

    pub async fn list_rules(
        &self,
        location: &LocationPattern,
    ) -> Result<MatchedLocationRules, ListRulesError> {
        let txn = self
            .db
            .begin()
            .await
            .context(list_rules_error::BeginTransactionSnafu)?;

        let (location_id, location_pattern) = Self::match_location_internal(&txn, location, false)
            .await
            .context(list_rules_error::MatchLocationSnafu)?
            .context(NoMatchedLocationSnafu {
                location: location.clone(),
            })
            .context(list_rules_error::NoMatchedLocationSnafu)?;

        let mut rules = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .order_by_asc(rule::Column::CreatedAt)
            .all(&txn)
            .await
            .context(list_rules_error::LoadRulesSnafu)?;
        deduplicate_rules(&mut rules);

        txn.commit().await.context(list_rules_error::CommitSnafu)?;

        Ok(MatchedLocationRules {
            location: location_pattern,
            rules,
        })
    }

    pub async fn list_rules_by_pattern(
        &self,
        location: &LocationPattern,
    ) -> Result<MatchedLocationRules, ListRulesByPatternError> {
        let txn = self
            .db
            .begin()
            .await
            .context(list_rules_by_pattern_error::BeginTransactionSnafu)?;

        let (location_id, location_pattern) = Self::match_location_internal(&txn, location, true)
            .await
            .context(list_rules_by_pattern_error::MatchLocationSnafu)?
            .context(LocationNotExistSnafu {
                location: location.clone(),
            })
            .context(list_rules_by_pattern_error::LocationNotExistSnafu)?;

        let mut rules = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .order_by_asc(rule::Column::CreatedAt)
            .all(&txn)
            .await
            .context(list_rules_by_pattern_error::LoadRulesSnafu)?;
        deduplicate_rules(&mut rules);

        txn.commit()
            .await
            .context(list_rules_by_pattern_error::CommitSnafu)?;

        Ok(MatchedLocationRules {
            location: location_pattern,
            rules,
        })
    }

    pub async fn remove_rule_set(
        &self,
        location: &LocationPattern,
    ) -> Result<(), RemoveRuleSetError> {
        let txn = self
            .db
            .begin()
            .await
            .context(remove_rule_set_error::BeginTransactionSnafu)?;

        let (location_id, ..) = Self::match_location_internal(&txn, location, true)
            .await
            .context(remove_rule_set_error::MatchLocationSnafu)?
            .context(LocationNotExistSnafu {
                location: location.clone(),
            })
            .context(remove_rule_set_error::LocationNotExistSnafu)?;

        location::Entity::delete_by_id(location_id)
            .exec(&txn)
            .await
            .context(remove_rule_set_error::DeleteRuleSetSnafu)?;
        txn.commit()
            .await
            .context(remove_rule_set_error::CommitSnafu)?;
        Ok(())
    }

    pub async fn list_all_rules(&self) -> Result<AllLocationRules, ListAllRulesError> {
        let txn = self
            .db
            .begin()
            .await
            .context(list_all_rules_error::BeginTransactionSnafu)?;

        let locations = location::Entity::find()
            .all(&txn)
            .await
            .context(list_all_rules_error::LoadLocationsSnafu)?;
        let rules = locations
            .load_many(rule::Entity, &txn)
            .await
            .context(list_all_rules_error::LoadRulesSnafu)?;

        #[allow(clippy::mutable_key_type)]
        let map = locations
            .into_iter()
            .zip(rules)
            .map(|(location, mut rules)| {
                deduplicate_rules(&mut rules);
                let pattern_with_time = PatternWithTime::new(
                    location.created_at.timestamp_micros(),
                    location.pattern.clone(),
                );
                rules.sort_by_key(|rule| rule.created_at);
                (pattern_with_time, (location, rules))
            })
            .collect();

        txn.commit()
            .await
            .context(list_all_rules_error::CommitSnafu)?;
        Ok(AllLocationRules { map })
    }

    pub async fn remove_rules(
        &self,
        location: &LocationPattern,
        sequence: impl IntoIterator<Item = usize>,
    ) -> Result<(), RemoveRulesError> {
        let txn = self
            .db
            .begin()
            .await
            .context(remove_rules_error::BeginTransactionSnafu)?;

        let (location_id, ..) = Self::match_location_internal(&txn, location, true)
            .await
            .context(remove_rules_error::MatchLocationSnafu)?
            .context(LocationNotExistSnafu {
                location: location.clone(),
            })
            .context(RuleSetNotExistSnafu)
            .context(remove_rules_error::RuleSnafu)?;

        let rule_ids: Vec<i32> = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .order_by_asc(rule::Column::CreatedAt)
            .select_only()
            .column(rule::Column::Id)
            .into_tuple()
            .all(&txn)
            .await
            .context(remove_rules_error::LoadRuleIdsSnafu)?;

        let ids_to_delete = sequence
            .into_iter()
            .map(|seq| {
                rule_ids
                    .get(seq)
                    .copied()
                    .context(RuleNotExistSnafu { seq })
            })
            .try_fold(vec![], |mut set, id| {
                id.map(move |id| {
                    set.push(id);
                    set
                })
            })
            .context(remove_rules_error::RuleSnafu)?;

        rule::Entity::delete_many()
            .filter(rule::Column::Id.is_in(ids_to_delete))
            .exec(&txn)
            .await
            .context(remove_rules_error::DeleteRulesSnafu)?;

        txn.commit()
            .await
            .context(remove_rules_error::CommitSnafu)?;

        Ok(())
    }

    pub async fn remove_rules_by_ids(
        &self,
        location: &LocationPattern,
        ids: impl IntoIterator<Item = i32>,
    ) -> Result<(), RemoveRulesByIdsError> {
        let txn = self
            .db
            .begin()
            .await
            .context(remove_rules_by_ids_error::BeginTransactionSnafu)?;

        let (location_id, ..) = Self::match_location_internal(&txn, location, true)
            .await
            .context(remove_rules_by_ids_error::MatchLocationSnafu)?
            .context(LocationNotExistSnafu {
                location: location.clone(),
            })
            .context(RemoveRuleSetByIdNotExistSnafu)
            .context(remove_rules_by_ids_error::RuleSnafu)?;

        let requested_ids: Vec<i32> = ids.into_iter().collect();
        let requested_set: BTreeSet<i32> = requested_ids.iter().copied().collect();

        let matched_rules = rule::Entity::find()
            .filter(rule::Column::Id.is_in(requested_set.iter().copied()))
            .all(&txn)
            .await
            .context(remove_rules_by_ids_error::LoadRulesSnafu)?;

        if matched_rules.len() != requested_set.len() {
            let found_ids: BTreeSet<i32> = matched_rules.iter().map(|rule| rule.id).collect();
            let missing_id = requested_set
                .iter()
                .find(|id| !found_ids.contains(id))
                .copied()
                .unwrap_or_default();
            return RemoveRuleIdNotExistSnafu { id: missing_id }
                .fail()
                .context(remove_rules_by_ids_error::RuleSnafu);
        }

        if let Some(foreign_id) = matched_rules
            .iter()
            .find(|rule| rule.location_id != location_id)
            .map(|rule| rule.id)
        {
            return RemoveRuleIdNotExistSnafu { id: foreign_id }
                .fail()
                .context(remove_rules_by_ids_error::RuleSnafu);
        }

        rule::Entity::delete_many()
            .filter(rule::Column::Id.is_in(requested_set.iter().copied()))
            .exec(&txn)
            .await
            .context(remove_rules_by_ids_error::DeleteRulesSnafu)?;

        txn.commit()
            .await
            .context(remove_rules_by_ids_error::CommitSnafu)?;

        Ok(())
    }

    async fn match_or_create_location_internal(
        txn: &DatabaseTransaction,
        location: &LocationPattern,
    ) -> Result<i32, MatchOrCreateLocationError> {
        match Self::match_location_internal(txn, location, true)
            .await
            .context(match_or_create_location_error::MatchLocationSnafu)?
        {
            Some((id, ..)) => Ok(id),
            None => {
                let now = chrono::Utc::now();
                let new_location = location::ActiveModel {
                    pattern: Set(location.clone()),
                    created_at: Set(now),
                    updated_at: Set(now),
                    ..Default::default()
                };
                let res = location::Entity::insert(new_location)
                    .exec(txn)
                    .await
                    .context(match_or_create_location_error::InsertLocationSnafu)?;
                Ok(res.last_insert_id)
            }
        }
    }

    async fn append_rule_internal(
        &self,
        location: &LocationPattern,
        action: RequestAction,
        expr: LocationRuleExprs,
    ) -> Result<rule::Model, AppendRuleError> {
        let txn = self
            .db
            .begin()
            .await
            .context(append_rule_error::BeginTransactionSnafu)?;

        let location_id = Self::match_or_create_location_internal(&txn, location)
            .await
            .context(append_rule_error::MatchOrCreateLocationSnafu)?;

        let existing_rules = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .filter(rule::Column::Action.eq(action))
            .order_by_asc(rule::Column::CreatedAt)
            .all(&txn)
            .await
            .context(append_rule_error::LoadExistingRulesSnafu)?;
        if let Some(existing_rule) = existing_rules
            .into_iter()
            .find(|candidate| candidate.exprs.polish() == expr.polish())
        {
            txn.commit().await.context(append_rule_error::CommitSnafu)?;
            return Ok(existing_rule);
        }

        let now = chrono::Utc::now();
        let new_rule = rule::ActiveModel {
            location_id: Set(location_id),
            action: Set(action),
            exprs: Set(expr),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let result = rule::Entity::insert(new_rule)
            .exec(&txn)
            .await
            .context(append_rule_error::InsertRuleSnafu)?;

        let inserted_rule = rule::Entity::find_by_id(result.last_insert_id)
            .one(&txn)
            .await
            .context(append_rule_error::LoadInsertedRuleSnafu)?
            .context(append_rule_error::InsertedRuleMissingSnafu {
                id: result.last_insert_id,
            })?;

        txn.commit().await.context(append_rule_error::CommitSnafu)?;

        Ok(inserted_rule)
    }

    pub async fn append_rule(
        &self,
        location: &LocationPattern,
        action: RequestAction,
        expr: LocationRuleExprs,
    ) -> Result<(), AppendRuleError> {
        self.append_rule_internal(location, action, expr)
            .await
            .map(|_| ())
    }

    pub async fn append_rule_with_id(
        &self,
        location: &LocationPattern,
        action: RequestAction,
        expr: LocationRuleExprs,
    ) -> Result<rule::Model, AppendRuleError> {
        self.append_rule_internal(location, action, expr).await
    }

    pub async fn replace_rule_by_id(
        &self,
        location: &LocationPattern,
        id: i32,
        action: RequestAction,
        expr: LocationRuleExprs,
    ) -> Result<rule::Model, ReplaceRuleByIdError> {
        let txn = self
            .db
            .begin()
            .await
            .context(replace_rule_by_id_error::BeginTransactionSnafu)?;

        let (location_id, ..) = Self::match_location_internal(&txn, location, true)
            .await
            .context(replace_rule_by_id_error::MatchLocationSnafu)?
            .context(LocationNotExistSnafu {
                location: location.clone(),
            })
            .context(ReplaceRuleSetByIdNotExistSnafu)
            .context(replace_rule_by_id_error::RuleSnafu)?;

        let current_rule = rule::Entity::find_by_id(id)
            .one(&txn)
            .await
            .context(replace_rule_by_id_error::LoadRuleSnafu)?
            .context(ReplaceRuleIdNotExistSnafu { id })
            .context(replace_rule_by_id_error::RuleSnafu)?;

        if current_rule.location_id != location_id {
            return ReplaceRuleIdNotExistSnafu { id }
                .fail()
                .context(replace_rule_by_id_error::RuleSnafu);
        }

        let mut updated_rule: rule::ActiveModel = current_rule.into();
        updated_rule.action = Set(action);
        updated_rule.exprs = Set(expr);
        updated_rule.updated_at = Set(chrono::Utc::now());

        let updated_rule = updated_rule
            .update(&txn)
            .await
            .context(replace_rule_by_id_error::UpdateRuleSnafu)?;

        txn.commit()
            .await
            .context(replace_rule_by_id_error::CommitSnafu)?;

        Ok(updated_rule)
    }
}
