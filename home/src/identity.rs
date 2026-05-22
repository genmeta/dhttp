use std::path::{Path, PathBuf};

use crate::DhttpHome;
use snafu::{OptionExt, ResultExt, Snafu};

use dhttp_identity::name::{DhttpName, InvalidDhttpName};

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

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IdentityHomeFromPathError {
    #[snafu(display("identity home path has no directory name: {}", path.display()))]
    MissingFileName { path: PathBuf },
    #[snafu(display("identity home directory name is not valid unicode: {}", path.display()))]
    NonUtf8FileName { path: PathBuf },
    #[snafu(display("failed to parse identity home directory name as dhttp name"))]
    InvalidName { source: InvalidDhttpName },
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

    fn try_from_path(path: PathBuf) -> Result<Self, IdentityHomeFromPathError> {
        use identity_home_from_path_error::*;

        let file_name = path
            .file_name()
            .context(MissingFileNameSnafu { path: &path })?;
        let file_name = file_name
            .to_str()
            .context(NonUtf8FileNameSnafu { path: &path })?;
        let name = file_name.parse::<DhttpName>().context(InvalidNameSnafu)?;
        Ok(Self { path, name })
    }
}

impl TryFrom<PathBuf> for IdentityHome {
    type Error = IdentityHomeFromPathError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from_path(path)
    }
}

impl TryFrom<&Path> for IdentityHome {
    type Error = IdentityHomeFromPathError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::try_from_path(path.to_path_buf())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_home_from_path_uses_directory_name_as_dhttp_name() {
        let home = IdentityHome::try_from(PathBuf::from("/tmp/reimu.pilot")).unwrap();

        assert_eq!(home.path(), Path::new("/tmp/reimu.pilot"));
        assert_eq!(home.name().as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn identity_home_from_path_rejects_path_without_directory_name() {
        let error = IdentityHome::try_from(Path::new("/")).unwrap_err();

        assert!(matches!(
            error,
            IdentityHomeFromPathError::MissingFileName { .. }
        ));
    }

    #[test]
    fn identity_home_from_path_rejects_invalid_directory_name() {
        let error = IdentityHome::try_from(Path::new("/tmp/123")).unwrap_err();

        assert!(matches!(
            error,
            IdentityHomeFromPathError::InvalidName { .. }
        ));
    }
}
