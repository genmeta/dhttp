pub mod identity;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

#[derive(Debug, Clone)]
pub struct DhttpConfig {
    path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocateDhttpConfigError {
    #[cfg(any(unix, windows))]
    #[snafu(display("cannot locate user config directory"))]
    NoUserHome {},
    #[snafu(display(
        "dhttp config cannot be automatically located on this platform, try setting DHTTP_CONFIG environment variable"
    ))]
    UnsupportedPlatform {},
}

impl DhttpConfig {
    pub const DIR_NAME: &str = ".dhttp";

    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn for_user_home_dir(home_dir: impl Into<PathBuf>) -> Self {
        Self::new(home_dir.into().join(Self::DIR_NAME))
    }

    pub fn load_from_environment() -> Result<Self, LocateDhttpConfigError> {
        if let Some(path) = std::env::var_os("DHTTP_CONFIG") {
            return Ok(Self::new(PathBuf::from(path)));
        }

        #[cfg(any(unix, windows))]
        return Ok(Self::for_user_home_dir(
            dirs::home_dir().context(locate_dhttp_config_error::NoUserHomeSnafu)?,
        ));

        #[allow(unreachable_code)]
        locate_dhttp_config_error::UnsupportedPlatformSnafu.fail()
    }

    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl AsRef<Path> for DhttpConfig {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}
