pub mod certificate;
pub mod identity;

mod bootstrap;

use std::path::{Path, PathBuf};

use snafu::{OptionExt, Snafu};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidName;

impl std::fmt::Display for InvalidName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid DHTTP name")
    }
}

impl std::error::Error for InvalidName {}

pub const DHTTP_SUFFIX: &str = ".dhttp.net";

/// Expand a partial DHTTP identity name and return its canonical DNS form.
pub fn normalize_name(input: &str) -> Option<String> {
    let name = input.trim().to_ascii_lowercase();
    let name = if name.ends_with(DHTTP_SUFFIX) {
        name
    } else if let Some(partial) = name.strip_suffix('~') {
        format!("{partial}{DHTTP_SUFFIX}")
    } else {
        format!("{name}{DHTTP_SUFFIX}")
    };
    is_valid_dns_name(&name).then_some(name)
}

/// Normalize a lookup name, expanding only an explicit trailing `~`.
/// Ordinary DNS names retain their namespace; single-label hosts are allowed.
pub fn normalize_dns_name(input: &str) -> Option<String> {
    let name = input.trim().to_ascii_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let name = if let Some(partial) = name.strip_suffix('~') {
        format!("{partial}{DHTTP_SUFFIX}")
    } else {
        name.to_owned()
    };
    is_valid_dns_labels(&name).then_some(name)
}

/// Check certserver's canonical lowercase ASCII DNS label rules.
pub fn is_valid_dns_name(name: &str) -> bool {
    name.split('.').count() >= 2 && is_valid_dns_labels(name)
}

fn is_valid_dns_labels(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub fn validate_name(input: &str) -> Result<(), InvalidName> {
    (normalize_name(input).as_deref() == Some(input))
        .then_some(())
        .ok_or(InvalidName)
}

const USER_HOME_ENV: &str = "DHTTP_HOME";
const GLOBAL_HOME_ENV: &str = "DHTTP_GLOBAL_HOME";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_UNIX_GLOBAL_HOME: &str = "/etc/dhttp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeScope {
    User,
    Global,
}

/// A handle to the user's dhttp home directory (e.g. `~/.dhttp/`).
///
/// `DhttpHome` describes a directory that contains per-identity profiles.
/// It does not own any in-memory configuration data;
/// it is purely a typed path with helpers for resolving the layout inside.
#[derive(Debug, Clone)]
pub struct DhttpHome {
    path: PathBuf,
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
#[path = "../tests/unit/home.rs"]
mod tests;
