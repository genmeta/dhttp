use std::path::{Path, PathBuf};

use crate::DhttpHome;
use snafu::{OptionExt, ResultExt, Snafu};

use dhttp_identity::name::{DhttpName, InvalidDhttpName};

#[cfg(feature = "settings")]
pub mod settings;
#[cfg(feature = "ssl")]
pub mod ssl;

/// A handle to a per-identity profile directory (e.g. `~/.dhttp/reimu.pilot/`).
///
/// `IdentityProfile` is one of N sibling directories living inside a `DhttpHome`.
/// Each profile owns that identity's certificate, private key, server config,
/// and access database. The type is a typed path; it performs no IO on
/// construction.
#[derive(Debug, Clone)]
pub struct IdentityProfile {
    pub(crate) path: PathBuf,
    pub(crate) name: DhttpName<'static>,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IdentityProfileFromPathError {
    #[snafu(display("identity profile path has no directory name: {}", path.display()))]
    MissingFileName { path: PathBuf },
    #[snafu(display("identity profile directory name is not valid unicode: {}", path.display()))]
    NonUtf8FileName { path: PathBuf },
    #[snafu(display("failed to parse identity profile directory name as dhttp name"))]
    InvalidName { source: InvalidDhttpName },
}

impl IdentityProfile {
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

    fn try_from_path(path: PathBuf) -> Result<Self, IdentityProfileFromPathError> {
        use identity_profile_from_path_error::*;

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

impl TryFrom<PathBuf> for IdentityProfile {
    type Error = IdentityProfileFromPathError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from_path(path)
    }
}

impl TryFrom<&Path> for IdentityProfile {
    type Error = IdentityProfileFromPathError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::try_from_path(path.to_path_buf())
    }
}

impl DhttpHome {
    pub fn join_identity_name(&self, name: DhttpName<'_>) -> PathBuf {
        self.join(name.as_partial())
    }

    /// Construct an [`IdentityProfile`] handle for `name` without touching disk.
    ///
    /// Use this when you only need the typed path (for example to compute a
    /// child file path). To verify that the directory actually exists, call
    /// [`DhttpHome::resolve_identity_profile`] instead.
    pub fn identity_profile(&self, name: DhttpName<'_>) -> IdentityProfile {
        IdentityProfile {
            path: self.join_identity_name(name.clone()),
            name: name.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_profile_from_path_uses_directory_name_as_dhttp_name() {
        let profile = IdentityProfile::try_from(PathBuf::from("/tmp/reimu.pilot")).unwrap();

        assert_eq!(profile.path(), Path::new("/tmp/reimu.pilot"));
        assert_eq!(profile.name().as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn identity_profile_from_path_rejects_path_without_directory_name() {
        let error = IdentityProfile::try_from(Path::new("/")).unwrap_err();

        assert!(matches!(
            error,
            IdentityProfileFromPathError::MissingFileName { .. }
        ));
    }

    #[test]
    fn identity_profile_from_path_rejects_invalid_directory_name() {
        let error = IdentityProfile::try_from(Path::new("/tmp/123")).unwrap_err();

        assert!(matches!(
            error,
            IdentityProfileFromPathError::InvalidName { .. }
        ));
    }
}
