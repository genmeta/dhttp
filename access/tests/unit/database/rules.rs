#[tokio::test]
async fn appending_duplicate_rules_is_idempotent() {
    let test_home = TestHome::new("duplicate-rules");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);

    let first = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "alice.pilot~".parse().unwrap(),
        )
        .await
        .unwrap();
    let first_rules = service
        .list_rules_by_pattern(&"/api".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(first_rules.rules.len(), 1);

    let duplicate = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "alice.pilot.dhttp.net".parse().unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(duplicate.id, first.id);
    let rules = service
        .list_rules_by_pattern(&"/api".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(rules.rules.len(), 1);
}

#[tokio::test]
async fn concurrent_appends_are_idempotent() {
    let test_home = TestHome::new("concurrent-duplicate-rules");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);
    let location = "/api".parse().unwrap();
    let expr: crate::expr::exprs::LocationRuleExprs = "alice.pilot~".parse().unwrap();

    let (first, second) = tokio::join!(
        service.append_rule_with_id(&location, RequestAction::Allow, expr.clone()),
        service.append_rule_with_id(&location, RequestAction::Allow, expr),
    );
    let first = first.unwrap();
    let second = second.unwrap();

    assert_eq!(first.id, second.id);
    assert_eq!(
        service
            .list_rules_by_pattern(&location)
            .await
            .unwrap()
            .rules
            .len(),
        1
    );
}

async fn insert_duplicate_rule(db: &DatabaseConnection, original: &rule::Model) {
    db.execute_unprepared("DROP INDEX idx_location_rules_logical_unique")
        .await
        .unwrap();

    let now = chrono::Utc::now();
    rule::Entity::insert(rule::ActiveModel {
        location_id: Set(original.location_id),
        action: Set(original.action),
        exprs: Set(original.exprs.clone()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    })
    .exec(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn removing_rule_by_sequence_removes_duplicate_rows() {
    let test_home = TestHome::new("remove-duplicate-by-sequence");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);
    let original = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "alice.pilot~".parse().unwrap(),
        )
        .await
        .unwrap();

    insert_duplicate_rule(&db, &original).await;
    service
        .remove_rules(&"/api".parse().unwrap(), [0])
        .await
        .unwrap();

    assert!(
        service
            .list_rules_by_pattern(&"/api".parse().unwrap())
            .await
            .unwrap()
            .rules
            .is_empty()
    );
}

#[tokio::test]
async fn removing_rule_by_id_removes_duplicate_rows() {
    let test_home = TestHome::new("remove-duplicate-by-id");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);
    let original = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "alice.pilot~".parse().unwrap(),
        )
        .await
        .unwrap();

    insert_duplicate_rule(&db, &original).await;
    service
        .remove_rules_by_ids(&"/api".parse().unwrap(), [original.id])
        .await
        .unwrap();

    assert!(
        service
            .list_rules_by_pattern(&"/api".parse().unwrap())
            .await
            .unwrap()
            .rules
            .is_empty()
    );
}
