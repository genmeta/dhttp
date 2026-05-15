use std::path::{Path, PathBuf};

use crate::DhttpHome;

pub use dhttp_identity::{DhttpName, InvalidName, Name};

#[cfg(feature = "default-config")]
pub mod default;
#[cfg(feature = "ssl")]
pub mod ssl;

/// An identity home directory (e.g. `.dhttp/reimu.pilot/`).
#[derive(Debug, Clone)]
pub struct IdentityHome {
    pub(crate) path: PathBuf,
    pub(crate) name: DhttpName<'static>,
}

impl IdentityHome {
    pub const LOGS_DIR: &'static str = "logs";
    pub const ACCESS_LOG_FILE: &'static str = "access.log";
    pub const DB_DIR: &'static str = "db";
    pub const ACCESS_DB_FILE: &'static str = "access.db";
    pub const SERVER_CONF_FILE: &'static str = "server.conf";

    pub fn name(&self) -> &DhttpName<'static> {
        &self.name
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn join(&self, sub: impl AsRef<Path>) -> PathBuf {
        self.path.join(sub)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.join(Self::LOGS_DIR)
    }

    pub fn access_log_path(&self) -> PathBuf {
        self.logs_dir().join(Self::ACCESS_LOG_FILE)
    }

    pub fn access_db_path(&self) -> PathBuf {
        self.join(Self::DB_DIR).join(Self::ACCESS_DB_FILE)
    }

    pub fn server_conf_path(&self) -> PathBuf {
        self.join(Self::SERVER_CONF_FILE)
    }
}

impl DhttpHome {
    pub fn join_identity_name(&self, name: DhttpName<'_>) -> PathBuf {
        self.join(name.as_partial())
    }

    pub fn identity_home(&self, name: DhttpName<'_>) -> IdentityHome {
        IdentityHome {
            path: self.join_identity_name(name.clone()),
            name: name.to_owned(),
        }
    }
}
