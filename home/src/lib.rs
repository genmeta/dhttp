pub mod identity;

mod bootstrap;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

const USER_HOME_ENV: &str = "DHTTP_HOME";
const GLOBAL_HOME_ENV: &str = "DHTTP_GLOBAL_HOME";
const DEFAULT_UNIX_GLOBAL_HOME: &str = "/etc/dhttp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeScope {
    User,
    Global,
}

/// A handle to the user's dhttp home directory (e.g. `~/.dhttp/`).
///
/// `DhttpHome` describes a directory that contains per-identity profiles and
/// a global settings file. It does not own any in-memory configuration data;
/// it is purely a typed path with helpers for resolving the layout inside.
#[derive(Debug, Clone)]
pub struct DhttpHome {
    path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocateDhttpHomeError {
    #[cfg(any(unix, windows))]
    #[snafu(display("cannot locate user home directory"))]
    NoUserHome {},
    #[snafu(display(
        "dhttp home cannot be automatically located on this platform, try setting DHTTP_HOME environment variable"
    ))]
    UnsupportedPlatform {},
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LoadDhttpHomeError {
    #[cfg(any(unix, windows))]
    #[snafu(display("cannot locate user home directory"))]
    NoUserHome {},
    #[snafu(display("global dhttp home is not configured"))]
    GlobalHomeNotConfigured {},
    #[snafu(display(
        "dhttp home cannot be automatically located on this platform, try setting DHTTP_HOME environment variable"
    ))]
    UnsupportedPlatform {},
}

impl DhttpHome {
    pub const DIR_NAME: &str = ".dhttp";

    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn for_user_home_dir(home_dir: impl Into<PathBuf>) -> Self {
        Self::new(home_dir.into().join(Self::DIR_NAME))
    }

    pub fn load(scope: HomeScope) -> Result<Self, LoadDhttpHomeError> {
        match scope {
            HomeScope::User => Ok(Self::new(resolve_user_home_path(
                std::env::var_os(USER_HOME_ENV).map(PathBuf::from),
                user_home_dir(),
            )?)),
            HomeScope::Global => Ok(Self::new(resolve_global_home_path(
                std::env::var_os(GLOBAL_HOME_ENV).map(PathBuf::from),
                bootstrap::DHTTP_GLOBAL_HOME,
                platform_default_global_home(),
            )?)),
        }
    }

    #[deprecated(note = "use DhttpHome::load(HomeScope::User) instead")]
    pub fn load_from_environment() -> Result<Self, LocateDhttpHomeError> {
        if let Some(path) = std::env::var_os(USER_HOME_ENV) {
            return Ok(Self::new(PathBuf::from(path)));
        }

        #[cfg(any(unix, windows))]
        return Ok(Self::for_user_home_dir(
            dirs::home_dir().context(locate_dhttp_home_error::NoUserHomeSnafu)?,
        ));

        #[allow(unreachable_code)]
        locate_dhttp_home_error::UnsupportedPlatformSnafu.fail()
    }

    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl AsRef<Path> for DhttpHome {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

fn resolve_user_home_path(
    runtime_home: Option<PathBuf>,
    user_home_dir: Option<PathBuf>,
) -> Result<PathBuf, LoadDhttpHomeError> {
    if let Some(path) = runtime_home {
        return Ok(path);
    }

    #[cfg(any(unix, windows))]
    let home_dir = user_home_dir.context(load_dhttp_home_error::NoUserHomeSnafu)?;

    #[cfg(not(any(unix, windows)))]
    let home_dir = user_home_dir.context(load_dhttp_home_error::UnsupportedPlatformSnafu)?;

    Ok(home_dir.join(DhttpHome::DIR_NAME))
}

fn resolve_global_home_path(
    runtime_home: Option<PathBuf>,
    compiled_home: Option<&str>,
    default_home: Option<&str>,
) -> Result<PathBuf, LoadDhttpHomeError> {
    if let Some(path) = runtime_home {
        return Ok(path);
    }
    if let Some(path) = compiled_home {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = default_home {
        return Ok(PathBuf::from(path));
    }

    load_dhttp_home_error::GlobalHomeNotConfiguredSnafu.fail()
}

fn user_home_dir() -> Option<PathBuf> {
    #[cfg(any(unix, windows))]
    {
        return dirs::home_dir();
    }

    #[allow(unreachable_code)]
    None
}

fn platform_default_global_home() -> Option<&'static str> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return Some(DEFAULT_UNIX_GLOBAL_HOME);
    }

    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{LoadDhttpHomeError, resolve_global_home_path, resolve_user_home_path};

    #[test]
    fn user_scope_path_prefers_runtime_home_env() {
        let path = resolve_user_home_path(
            Some(PathBuf::from("/runtime/dhttp-home")),
            Some(PathBuf::from("/home/reimu")),
        )
        .expect("user path should resolve");

        assert_eq!(path, PathBuf::from("/runtime/dhttp-home"));
    }

    #[test]
    fn user_scope_path_falls_back_to_user_home_dir() {
        let path = resolve_user_home_path(None, Some(PathBuf::from("/home/reimu")))
            .expect("user path should resolve");

        assert_eq!(path, PathBuf::from("/home/reimu/.dhttp"));
    }

    #[test]
    fn global_scope_path_prefers_runtime_env_over_compile_time_and_default() {
        let path = resolve_global_home_path(
            Some(PathBuf::from("/runtime/global")),
            Some("/compiled/global"),
            Some("/etc/dhttp"),
        )
        .expect("global path should resolve");

        assert_eq!(path, PathBuf::from("/runtime/global"));
    }

    #[test]
    fn global_scope_path_uses_compile_time_home_when_runtime_is_missing() {
        let path = resolve_global_home_path(None, Some("/compiled/global"), Some("/etc/dhttp"))
            .expect("global path should resolve");

        assert_eq!(path, PathBuf::from("/compiled/global"));
    }

    #[test]
    fn global_scope_path_uses_platform_default_when_overrides_are_missing() {
        let path = resolve_global_home_path(None, None, Some("/etc/dhttp"))
            .expect("global path should resolve");

        assert_eq!(path, PathBuf::from("/etc/dhttp"));
    }

    #[test]
    fn global_scope_path_errors_when_no_source_is_available() {
        let error = resolve_global_home_path(None, None, None)
            .expect_err("missing global path sources must fail");

        assert!(matches!(
            error,
            LoadDhttpHomeError::GlobalHomeNotConfigured {}
        ));
    }
}
