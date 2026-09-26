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
            .order_by_asc(rule::Column::Id)
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
            .order_by_asc(rule::Column::Id)
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
                rules.sort_by_key(|rule| (rule.created_at, rule.id));
                (pattern_with_time, (location, rules))
            })
            .collect();

        txn.commit()
            .await
            .context(list_all_rules_error::CommitSnafu)?;
        Ok(AllLocationRules { map })
    }
}
