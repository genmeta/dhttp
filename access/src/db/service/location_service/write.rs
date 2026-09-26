impl LocationService<'_> {
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
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .try_insert()
                    .exec(txn)
                    .await
                    .context(match_or_create_location_error::InsertLocationSnafu)?;
                match res {
                    TryInsertResult::Inserted(res) => Ok(res.last_insert_id),
                    TryInsertResult::Conflicted => location::Entity::find()
                        .filter(location::Column::Pattern.eq(location.clone()))
                        .select_only()
                        .column(location::Column::Id)
                        .into_tuple()
                        .one(txn)
                        .await
                        .context(match_or_create_location_error::InsertLocationSnafu)?
                        .context(match_or_create_location_error::LocationMissingSnafu),
                    TryInsertResult::Empty => unreachable!("inserting one location is not empty"),
                }
            }
        }
    }

    async fn refresh_rule_priority(
        txn: &DatabaseTransaction,
        existing_rule: rule::Model,
    ) -> Result<rule::Model, AppendRuleError> {
        let now = chrono::Utc::now();
        let mut active_rule: rule::ActiveModel = existing_rule.into();
        active_rule.created_at = Set(now);
        active_rule.updated_at = Set(now);
        active_rule
            .update(txn)
            .await
            .context(append_rule_error::RefreshExistingRuleSnafu)
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
            .order_by_asc(rule::Column::Id)
            .all(&txn)
            .await
            .context(append_rule_error::LoadExistingRulesSnafu)?;
        let expr_polish = expr.polish().clone();
        if let Some(existing_rule) = existing_rules
            .into_iter()
            .find(|candidate| candidate.exprs.polish() == &expr_polish)
        {
            let existing_rule = Self::refresh_rule_priority(&txn, existing_rule).await?;
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
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .try_insert()
            .exec(&txn)
            .await
            .context(append_rule_error::InsertRuleSnafu)?;

        let inserted_rule = match result {
            TryInsertResult::Inserted(result) => {
                let id = result.last_insert_id;
                rule::Entity::find_by_id(id)
                    .one(&txn)
                    .await
                    .context(append_rule_error::LoadInsertedRuleSnafu)?
                    .context(append_rule_error::InsertedRuleMissingSnafu { id })?
            }
            TryInsertResult::Conflicted => {
                let existing_rule = rule::Entity::find()
                    .filter(rule::Column::LocationId.eq(location_id))
                    .filter(rule::Column::Action.eq(action))
                    .order_by_asc(rule::Column::CreatedAt)
                    .order_by_asc(rule::Column::Id)
                    .all(&txn)
                    .await
                    .context(append_rule_error::LoadExistingRulesSnafu)?
                    .into_iter()
                    .find(|candidate| candidate.exprs.polish() == &expr_polish)
                    .context(append_rule_error::ConflictingRuleMissingSnafu)?;
                Self::refresh_rule_priority(&txn, existing_rule).await?
            }
            TryInsertResult::Empty => unreachable!("inserting one rule is not empty"),
        };

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
