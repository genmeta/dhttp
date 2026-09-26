#[tokio::test]
async fn location_service_location_only_crud() {
    let test_home = TestHome::new("location-crud");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);

    service
        .append_rule(
            &"/api".parse().unwrap(),
            RequestAction::Deny,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();
    service
        .append_rule(
            &"/admin".parse().unwrap(),
            RequestAction::Allow,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();

    let listed = service.list_rule_sets().await.unwrap();
    assert_eq!(listed.0.len(), 2);

    let api_rules = service.list_rules(&"/api".parse().unwrap()).await.unwrap();
    assert_eq!(api_rules.rules.len(), 1);
    assert_eq!(api_rules.location.to_string(), "/api");

    service
        .remove_rule_set(&"/admin".parse().unwrap())
        .await
        .unwrap();
    let listed = service.list_rule_sets().await.unwrap();
    assert_eq!(listed.0.len(), 1);
}

#[tokio::test]
async fn location_only_matcher_behavior() {
    let test_home = TestHome::new("location-matcher");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);

    service
        .append_rule(
            &"/api".parse().unwrap(),
            RequestAction::Deny,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();

    let matcher = LocationRulesMatcher::from(service.list_all_rules().await.unwrap());
    let rules = matcher.match_rules("/api").unwrap();

    assert_eq!(rules.0.to_string(), "/api");
    assert_eq!(rules.1.len(), 1);
    assert_eq!(rules.1[0].1, RequestAction::Deny);

    let no_match = matcher.match_rules("/missing");
    assert!(no_match.is_err());
}

#[tokio::test]
async fn identity_store_isolation() {
    let test_home = TestHome::new("identity-isolation");
    let home = test_home.home();
    let alice: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let bob: identity::Name<'static> = "bob.pilot".parse().unwrap();

    let alice_db = init_identity_access_database(&home, alice.borrow())
        .await
        .unwrap();
    let bob_db = init_identity_access_database(&home, bob.borrow())
        .await
        .unwrap();

    LocationService::new(&alice_db)
        .append_rule(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();

    let alice_rules = LocationService::new(&alice_db)
        .list_rule_sets()
        .await
        .unwrap();
    let bob_rules = LocationService::new(&bob_db)
        .list_rule_sets()
        .await
        .unwrap();

    assert_eq!(alice_rules.0.len(), 1);
    assert!(bob_rules.0.is_empty());
}

#[tokio::test]
async fn service_rejects_foreign_rule_id() {
    let test_home = TestHome::new("foreign-rule-id");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);

    let api_rule = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();
    service
        .append_rule(
            &"/admin".parse().unwrap(),
            RequestAction::Deny,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();

    let replace_error = service
        .replace_rule_by_id(
            &"/admin".parse().unwrap(),
            api_rule.id,
            RequestAction::Deny,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        replace_error,
        service::error::ReplaceRuleByIdError::Rule {
            source: service::location_service::ReplaceRuleByIdFailed::ReplaceRuleIdNotExist { .. }
        }
    ));

    let delete_error = service
        .remove_rules_by_ids(&"/admin".parse().unwrap(), [api_rule.id])
        .await
        .unwrap_err();
    assert!(matches!(
        delete_error,
        service::error::RemoveRulesByIdsError::Rule {
            source: service::location_service::RemoveRuleByIdFailed::RemoveRuleIdNotExist { .. }
        }
    ));
}

#[tokio::test]
async fn service_id_batch_is_atomic() {
    let test_home = TestHome::new("id-batch-atomic");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();
    let service = LocationService::new(&db);

    let first_rule = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Allow,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();
    let second_rule = service
        .append_rule_with_id(
            &"/api".parse().unwrap(),
            RequestAction::Deny,
            "*?".parse().unwrap(),
        )
        .await
        .unwrap();

    let error = service
        .remove_rules_by_ids(&"/api".parse().unwrap(), [first_rule.id, 9_999_999])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        service::error::RemoveRulesByIdsError::Rule {
            source: service::location_service::RemoveRuleByIdFailed::RemoveRuleIdNotExist { .. }
        }
    ));

    let api_rules = service
        .list_rules_by_pattern(&"/api".parse().unwrap())
        .await
        .unwrap();
    let remaining_ids: Vec<i32> = api_rules.rules.into_iter().map(|rule| rule.id).collect();
    assert_eq!(remaining_ids, vec![first_rule.id, second_rule.id]);
}
