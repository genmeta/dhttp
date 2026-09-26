#[tokio::test]
async fn identity_access_db_path_adapter() {
    let test_home = TestHome::new("path-adapter");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();

    let path = access_db_path(&home, identity.borrow());
    assert_eq!(
        path,
        home.as_path()
            .join("alice.pilot")
            .join("db")
            .join("access.db")
    );
}

#[tokio::test]
async fn explicit_init_creates_identity_db() {
    let test_home = TestHome::new("explicit-init");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();

    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();

    assert!(access_db_path(&home, identity.borrow()).is_file());
    LocationService::new(&db).ensure_store().await.unwrap();
}

#[tokio::test]
async fn open_missing_identity_store_fails() {
    let test_home = TestHome::new("missing-store");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();

    let error = open_identity_access_database(&home, identity.borrow())
        .await
        .unwrap_err();
    assert!(matches!(error, AccessDbError::MissingStore { .. }));
}

#[tokio::test]
async fn location_only_schema_init_smoke() {
    let test_home = TestHome::new("schema-smoke");
    let home = test_home.home();
    let identity: identity::Name<'static> = "alice.pilot".parse().unwrap();
    let db = init_identity_access_database(&home, identity.borrow())
        .await
        .unwrap();

    let tables: Vec<String> = db
        .query_all_raw(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name".to_string(),
        ))
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| row.try_get::<String>("", "name").ok())
        .collect();

    assert!(tables.contains(&"location_rule_sets".to_string()));
    assert!(tables.contains(&"location_rules".to_string()));
    assert!(!tables.contains(&"domain_rule_sets".to_string()));
    assert!(!tables.contains(&"domain_rules".to_string()));
    assert!(!tables.contains(&"location_domain_rule_sets".to_string()));
}

#[tokio::test]
async fn migration_keeps_latest_duplicate_rule() {
    use sea_orm_migration::MigratorTrait;

    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, Some(1)).await.unwrap();

    let now = chrono::Utc::now();
    let location_id = location::Entity::insert(location::ActiveModel {
        pattern: Set("/api".parse().unwrap()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    })
    .exec(&db)
    .await
    .unwrap()
    .last_insert_id;
    let expr: crate::expr::exprs::LocationRuleExprs = "alice.pilot~".parse().unwrap();

    let mut inserted = Vec::new();
    for (action, created_at) in [
        (RequestAction::Allow, now - chrono::Duration::seconds(2)),
        (RequestAction::Deny, now - chrono::Duration::seconds(1)),
        (RequestAction::Allow, now),
    ] {
        let id = rule::Entity::insert(rule::ActiveModel {
            location_id: Set(location_id),
            action: Set(action),
            exprs: Set(expr.clone()),
            created_at: Set(created_at),
            updated_at: Set(created_at),
            ..Default::default()
        })
        .exec(&db)
        .await
        .unwrap()
        .last_insert_id;
        inserted.push((id, action));
    }

    migration::Migrator::up(&db, None).await.unwrap();
    let rules = rule::Entity::find()
        .filter(rule::Column::LocationId.eq(location_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(rules.len(), 2);
    assert!(
        rules
            .iter()
            .any(|rule| rule.id == inserted[1].0 && rule.action == RequestAction::Deny)
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule.id == inserted[2].0 && rule.action == RequestAction::Allow)
    );
    assert!(!rules.iter().any(|rule| rule.id == inserted[0].0));
}
