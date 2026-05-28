pub mod identity;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

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

impl DhttpHome {
    pub const DIR_NAME: &str = ".dhttp";

    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn for_user_home_dir(home_dir: impl Into<PathBuf>) -> Self {
        Self::new(home_dir.into().join(Self::DIR_NAME))
    }

    pub fn load_from_environment() -> Result<Self, LocateDhttpHomeError> {
        if let Some(path) = std::env::var_os("DHTTP_HOME") {
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
