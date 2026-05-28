//! Access DB contract overrides for the dhttp-home migration:
//! - No domain rule layer exists in this crate anymore.
//! - CLI is the only identity selection boundary.
//! - HTTP consumes a single already-open access DB connection.
//! - This crate composes identity-local paths on top of dhttp-home without modifying it.

pub mod entities;
pub mod identity;
pub mod service;

use std::path::{Path, PathBuf};

pub use crate as base;
#[cfg(feature = "migration")]
pub use crate::migration;
use dhttp_home::identity::IdentityProfile;
pub use identity::{DhttpHome, Name};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
#[cfg(feature = "migration")]
use sea_orm_migration::MigratorTrait;
use snafu::{ResultExt, Snafu};

pub const ACCESS_DB_DIRECTORY: &str = "db";
pub const ACCESS_DB_FILENAME: &str = "access.db";
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Snafu)]
pub enum AccessDbError {
    #[snafu(display("failed to locate DHTTP_HOME"))]
    LocateDhttpHome {
        source: identity::LocateDhttpHomeError,
    },

    #[snafu(display("access store does not exist at `{}`", path.display()))]
    MissingStore { path: PathBuf },

    #[snafu(display("failed to create access store directory `{}`", path.display()))]
    CreateStoreDirectory {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to connect access database `{uri}`"))]
    ConnectDatabase { uri: String, source: sea_orm::DbErr },

    #[snafu(display("failed to configure SQLite pragmas for access database"))]
    ConfigureDatabase { source: sea_orm::DbErr },

    #[cfg(feature = "migration")]
    #[snafu(display("failed to initialize access database schema"))]
    InitializeDatabase { source: sea_orm::DbErr },
}

pub fn load_dhttp_home() -> Result<DhttpHome, AccessDbError> {
    DhttpHome::load_from_environment().context(LocateDhttpHomeSnafu)
}

pub fn access_db_path(home: &DhttpHome, identity: identity::Name<'_>) -> PathBuf {
    home.join_identity_name(identity)
        .join(ACCESS_DB_DIRECTORY)
        .join(ACCESS_DB_FILENAME)
}

pub fn identity_access_db_path(identity_profile: &IdentityProfile) -> PathBuf {
    identity_profile
        .join(ACCESS_DB_DIRECTORY)
        .join(ACCESS_DB_FILENAME)
}

fn sqlite_uri(path: &Path, mode: &str) -> String {
    format!("sqlite://{}?mode={mode}", path.display())
}

async fn configure_sqlite(database: &DatabaseConnection) -> Result<(), AccessDbError> {
    database
        .execute_unprepared("PRAGMA foreign_keys = ON;")
        .await
        .context(ConfigureDatabaseSnafu)?;
    database
        .execute_unprepared("PRAGMA journal_mode = WAL;")
        .await
        .context(ConfigureDatabaseSnafu)?;
    database
        .execute_unprepared(&format!("PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};"))
        .await
        .context(ConfigureDatabaseSnafu)?;
    Ok(())
}

async fn connect_sqlite(path: &Path, mode: &str) -> Result<DatabaseConnection, AccessDbError> {
    let uri = sqlite_uri(path, mode);
    let mut connect_options = ConnectOptions::new(uri.clone());
    connect_options.sqlx_logging_level(tracing::log::LevelFilter::Debug);
    let database = Database::connect(connect_options)
        .await
        .context(ConnectDatabaseSnafu { uri })?;
    configure_sqlite(&database).await?;
    Ok(database)
}

// sea_orm_migration会打info日志
#[cfg(feature = "migration")]
pub async fn initial_database(
    database: &sea_orm::DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    let mut future = migration::Migrator::up(database, None);
    std::future::poll_fn(|cx| {
        let _subscriber_guard = (!tracing::enabled!(tracing::Level::DEBUG))
            .then(|| tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::new()));
        future.as_mut().poll(cx)
    })
    .await
}

pub async fn open_existing_access_database(
    path: impl AsRef<Path>,
) -> Result<DatabaseConnection, AccessDbError> {
    let path = path.as_ref();
    if !path.is_file() {
        return MissingStoreSnafu {
            path: path.to_path_buf(),
        }
        .fail();
    }

    connect_sqlite(path, "rw").await
}

#[cfg(feature = "migration")]
pub async fn init_access_database(
    path: impl AsRef<Path>,
) -> Result<DatabaseConnection, AccessDbError> {
    let path = path.as_ref();
    let Some(parent) = path.parent() else {
        return MissingStoreSnafu {
            path: path.to_path_buf(),
        }
        .fail();
    };

    std::fs::create_dir_all(parent).context(CreateStoreDirectorySnafu {
        path: parent.to_path_buf(),
    })?;

    let database = connect_sqlite(path, "rwc").await?;
    initial_database(&database)
        .await
        .context(InitializeDatabaseSnafu)?;
    Ok(database)
}

pub async fn open_identity_access_database(
    home: &DhttpHome,
    identity: identity::Name<'_>,
) -> Result<DatabaseConnection, AccessDbError> {
    open_existing_access_database(access_db_path(home, identity)).await
}

#[cfg(feature = "migration")]
pub async fn init_identity_access_database(
    home: &DhttpHome,
    identity: identity::Name<'_>,
) -> Result<DatabaseConnection, AccessDbError> {
    init_access_database(access_db_path(home, identity)).await
}

pub async fn open_access_database(
    identity_profile: &IdentityProfile,
) -> Result<DatabaseConnection, AccessDbError> {
    open_existing_access_database(identity_access_db_path(identity_profile)).await
}

#[cfg(feature = "migration")]
pub async fn init_access_database_for(
    identity_profile: &IdentityProfile,
) -> Result<DatabaseConnection, AccessDbError> {
    init_access_database(identity_access_db_path(identity_profile)).await
}

#[cfg(all(test, feature = "migration"))]
mod tests {
    use std::path::PathBuf;

    use crate::{action::RequestAction, matcher::LocationRulesMatcher};
    use sea_orm::{ConnectionTrait, Statement};

    use super::service::location_service::LocationService;
    use super::*;

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "dhttp-access-db-tests-{name}-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn home(&self) -> DhttpHome {
            DhttpHome::new(self.path.clone())
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

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
            .query_all(Statement::from_string(
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
}
