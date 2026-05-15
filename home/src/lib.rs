pub mod identity;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

#[derive(Debug, Clone)]
pub struct DhttpHome {
    path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocateDhttpHomeError {
    #[cfg(any(unix, windows))]
    #[snafu(display("cannot locate home directory"))]
    NoHome {},
    #[snafu(display(
        "DHTTP_HOME cannot be automatically located on this platform, try setting DHTTP_HOME environment variable"
    ))]
    UnsupportedPlatform {},
}

impl DhttpHome {
    pub const DIR_NAME: &str = ".dhttp";

    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn for_home(home_dir: impl Into<PathBuf>) -> Self {
        Self::new(home_dir.into().join(Self::DIR_NAME))
    }

    pub fn load_from_environment() -> Result<Self, LocateDhttpHomeError> {
        if let Some(path) = std::env::var_os("DHTTP_HOME") {
            return Ok(Self::new(PathBuf::from(path)));
        }

        #[cfg(any(unix, windows))]
        return Ok(Self::for_home(
            dirs::home_dir().context(locate_dhttp_home_error::NoHomeSnafu)?,
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
