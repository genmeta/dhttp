impl LocationService<'_> {
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

        let rules = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .order_by_asc(rule::Column::CreatedAt)
            .order_by_asc(rule::Column::Id)
            .all(&txn)
            .await
            .context(remove_rules_error::LoadRulesSnafu)?;
        let mut visible_rules = rules.clone();
        deduplicate_rules(&mut visible_rules);

        let selected_rules = sequence
            .into_iter()
            .map(|seq| {
                visible_rules
                    .get(seq)
                    .cloned()
                    .context(RuleNotExistSnafu { seq })
            })
            .try_fold(vec![], |mut set, id| {
                id.map(move |id| {
                    set.push(id);
                    set
                })
            })
            .context(remove_rules_error::RuleSnafu)?;
        let ids_to_delete: Vec<i32> = rules
            .iter()
            .filter(|candidate| {
                selected_rules
                    .iter()
                    .any(|selected| same_logical_rule(candidate, selected))
            })
            .map(|rule| rule.id)
            .collect();

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

        let mut rules = rule::Entity::find()
            .filter(rule::Column::LocationId.eq(location_id))
            .all(&txn)
            .await
            .context(remove_rules_by_ids_error::LoadRulesSnafu)?;
        let ids_to_delete: Vec<i32> = rules
            .drain(..)
            .filter(|candidate| {
                matched_rules
                    .iter()
                    .any(|selected| same_logical_rule(candidate, selected))
            })
            .map(|rule| rule.id)
            .collect();

        rule::Entity::delete_many()
            .filter(rule::Column::Id.is_in(ids_to_delete))
            .exec(&txn)
            .await
            .context(remove_rules_by_ids_error::DeleteRulesSnafu)?;

        txn.commit()
            .await
            .context(remove_rules_by_ids_error::CommitSnafu)?;

        Ok(())
    }
}
