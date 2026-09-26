//! Access DB contract overrides for the dhttp-home migration:
//! - No domain rule layer exists in this crate anymore.
//! - CLI is the only identity selection boundary.
//! - HTTP consumes a single already-open access DB connection.
//! - This crate composes identity-local paths on top of dhttp-home without modifying it.

pub mod entities;
pub mod evaluator;
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

pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Snafu)]
pub enum AccessDbError {
    #[snafu(display("failed to locate DHTTP_HOME"))]
    LocateDhttpHome {
        source: identity::LoadDhttpHomeError,
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
    DhttpHome::load(dhttp_home::HomeScope::User).context(LocateDhttpHomeSnafu)
}

pub fn access_db_path(home: &DhttpHome, identity: identity::Name<'_>) -> PathBuf {
    home.identity_profile(identity.as_full())
        .expect("validated DHTTP identity name")
        .access_db_path()
}

pub fn identity_access_db_path(identity_profile: &IdentityProfile) -> PathBuf {
    identity_profile.access_db_path()
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
#[path = "../../tests/unit/database/mod.rs"]
mod tests;
