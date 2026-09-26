use std::path::{Path, PathBuf};

use crate::DhttpHome;
use snafu::{OptionExt, Snafu};

use crate::{InvalidName, normalize_name};

pub(crate) fn normalize_profile_name(input: &str) -> Option<String> {
    if let Some(rest) = input.strip_prefix("*.") {
        Some(format!("*.{}", normalize_name(rest)?))
    } else {
        normalize_name(input)
    }
}

#[cfg(feature = "ssl")]
#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub certs: std::sync::Arc<Vec<rustls::pki_types::CertificateDer<'static>>>,
    pub key: std::sync::Arc<rustls::pki_types::PrivateKeyDer<'static>>,
    pub ocsp: std::sync::Arc<Vec<u8>>,
}

#[cfg(feature = "ssl")]
impl Identity {
    pub fn new(
        name: String,
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        ocsp: Vec<u8>,
    ) -> Self {
        Self {
            name,
            certs: std::sync::Arc::new(certs),
            key: std::sync::Arc::new(key),
            ocsp: std::sync::Arc::new(ocsp),
        }
    }
}

#[cfg(feature = "ssl")]
pub mod ssl;

/// A handle to a per-identity profile directory (e.g. `~/.dhttp/reimu.pilot/`).
///
/// `IdentityProfile` is one of N sibling directories living inside a `DhttpHome`.
/// Each profile defines the shared file layout for one identity.
/// The components that use those paths manage their own file contents.
/// This type does no IO on construction.
#[derive(Debug, Clone)]
pub struct IdentityProfile {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IdentityProfileFromPathError {
    #[snafu(display("identity profile path has no directory name: {}", path.display()))]
    MissingFileName { path: PathBuf },
    #[snafu(display("identity profile directory name is not valid unicode: {}", path.display()))]
    NonUtf8FileName { path: PathBuf },
    #[snafu(display("invalid identity profile directory name: {name}"))]
    InvalidName { name: String },
}

impl IdentityProfile {
    pub const CONFIG_DB_FILE: &'static str = "config.db";
    pub const DB_DIR: &'static str = "db";
    pub const ACCESS_DB_FILE: &'static str = "access.db";
    pub const APPS_DIR: &'static str = "apps";
    pub const PUBLIC_DIR: &'static str = "public";
    pub const LOGS_DIR: &'static str = "logs";
    pub const CERT_LOG_FILE: &'static str = "cert.log";
    pub const ACCESS_LOG_FILE: &'static str = "access.log";

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn join(&self, sub: impl AsRef<Path>) -> PathBuf {
        self.path.join(sub)
    }

    pub fn config_db_path(&self) -> PathBuf {
        self.join(Self::CONFIG_DB_FILE)
    }

    pub fn db_dir(&self) -> PathBuf {
        self.join(Self::DB_DIR)
    }

    pub fn access_db_path(&self) -> PathBuf {
        self.db_dir().join(Self::ACCESS_DB_FILE)
    }

    pub fn apps_dir(&self) -> PathBuf {
        self.join(Self::APPS_DIR)
    }

    pub fn public_dir(&self) -> PathBuf {
        self.join(Self::PUBLIC_DIR)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.join(Self::LOGS_DIR)
    }

    pub fn access_log_path(&self) -> PathBuf {
        self.logs_dir().join(Self::ACCESS_LOG_FILE)
    }

    pub fn cert_log_path(&self) -> PathBuf {
        self.logs_dir().join(Self::CERT_LOG_FILE)
    }

    fn try_from_path(path: PathBuf) -> Result<Self, IdentityProfileFromPathError> {
        use identity_profile_from_path_error::*;

        let file_name = path
            .file_name()
            .context(MissingFileNameSnafu { path: &path })?;
        let file_name = file_name
            .to_str()
            .context(NonUtf8FileNameSnafu { path: &path })?;
        let name = normalize_profile_name(file_name).ok_or_else(|| {
            IdentityProfileFromPathError::InvalidName {
                name: file_name.to_owned(),
            }
        })?;
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
    /// Discover direct identity profiles in `<home>/<identity>/ssl` layout.
    /// Invalid names, symlinks, and directories without an SSL directory are skipped.
    pub fn discover_identity_profiles(&self) -> std::io::Result<Vec<IdentityProfile>> {
        let metadata = std::fs::symlink_metadata(self.as_path())?;
        if !metadata.file_type().is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dhttp home is not a directory",
            ));
        }
        let mut profiles = Vec::new();
        for entry in std::fs::read_dir(self.as_path())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            let Ok(profile) = IdentityProfile::try_from(path.clone()) else {
                continue;
            };
            let Some(directory_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if normalize_profile_name(&directory_name).as_deref() != Some(profile.name())
                || directory_name != profile.name().strip_suffix(".dhttp.net").unwrap()
            {
                continue;
            }
            if std::fs::symlink_metadata(path.join("ssl"))
                .is_ok_and(|metadata| metadata.file_type().is_dir())
            {
                profiles.push(profile);
            }
        }
        profiles.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(profiles)
    }

    pub fn join_identity_name(&self, name: &str) -> Result<PathBuf, InvalidName> {
        let full = normalize_profile_name(name).ok_or(InvalidName)?;
        Ok(self.join(full.strip_suffix(".dhttp.net").unwrap()))
    }

    /// Construct an [`IdentityProfile`] handle for `name` without touching disk.
    ///
    /// Use this when you only need the typed path (for example to compute a
    /// child file path). To verify that the directory actually exists, call
    /// [`DhttpHome::resolve_identity_profile`] instead.
    pub fn identity_profile(&self, name: &str) -> Result<IdentityProfile, InvalidName> {
        Ok(IdentityProfile {
            path: self.join_identity_name(name)?,
            name: normalize_profile_name(name).ok_or(InvalidName)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_only_direct_profiles_with_ssl() {
        let root = std::env::temp_dir().join(format!(
            "dhttp-home-discovery-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("alice/ssl")).unwrap();
        std::fs::create_dir_all(root.join("bob/ssl")).unwrap();
        std::fs::create_dir_all(root.join("Bad/ssl")).unwrap();
        std::fs::create_dir_all(root.join("charlie")).unwrap();
        let found = DhttpHome::new(root.clone())
            .discover_identity_profiles()
            .unwrap();
        assert_eq!(
            found
                .iter()
                .map(|profile| profile.name())
                .collect::<Vec<_>>(),
            ["alice.dhttp.net", "bob.dhttp.net"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_identity_path_name() {
        let home = DhttpHome::new(PathBuf::from("/tmp/dhttp-home"));
        assert!(home.join_identity_name("../alice").is_err());
        assert!(home.join_identity_name("alice/name").is_err());
    }

    #[test]
    fn identity_profile_from_path_uses_directory_name_as_dhttp_name() {
        let profile = IdentityProfile::try_from(PathBuf::from("/tmp/reimu.pilot")).unwrap();

        assert_eq!(profile.path(), Path::new("/tmp/reimu.pilot"));
        assert_eq!(profile.name(), "reimu.pilot.dhttp.net");
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

    #[test]
    fn log_paths_use_the_profile_logs_directory() {
        let profile = IdentityProfile::try_from(Path::new("/tmp/reimu.pilot")).unwrap();
        assert_eq!(
            profile.cert_log_path(),
            PathBuf::from("/tmp/reimu.pilot/logs/cert.log")
        );
        assert_eq!(
            profile.access_log_path(),
            PathBuf::from("/tmp/reimu.pilot/logs/access.log")
        );
    }

    #[test]
    fn shared_layout_paths_use_the_profile_directory() {
        let profile = IdentityProfile::try_from(Path::new("/tmp/reimu.pilot")).unwrap();
        assert_eq!(
            profile.config_db_path(),
            PathBuf::from("/tmp/reimu.pilot/config.db")
        );
        assert_eq!(
            profile.access_db_path(),
            PathBuf::from("/tmp/reimu.pilot/db/access.db")
        );
        assert_eq!(profile.apps_dir(), PathBuf::from("/tmp/reimu.pilot/apps"));
        assert_eq!(
            profile.public_dir(),
            PathBuf::from("/tmp/reimu.pilot/public")
        );
    }
}
