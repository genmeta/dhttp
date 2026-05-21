use std::path::{Path, PathBuf};

use futures::TryStreamExt;

use crate::{error::DhttpError, identity::Identity};

type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Debug, Clone)]
pub struct Home(dhttp::home::DhttpHome);

#[derive(Debug, Clone)]
pub struct IdentityHome(dhttp::home::identity::IdentityHome);

impl Home {
    pub fn load() -> Result<Self> {
        dhttp::home::DhttpHome::load_from_environment()
            .map(Self)
            .map_err(|error| DhttpError::from_error("home.load", error))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(dhttp::home::DhttpHome::new(path.into()))
    }

    pub fn path(&self) -> &Path {
        self.0.as_path()
    }

    pub fn identity_home(&self, name: &str) -> Result<IdentityHome> {
        let name = parse_name("home.identity_home", name)?;
        Ok(IdentityHome(self.0.identity_home(name)))
    }

    pub async fn load_identity(&self, name: &str) -> Result<IdentityHome> {
        let name = parse_name("home.load_identity", name)?;
        self.0
            .load_identity(name)
            .await
            .map(IdentityHome)
            .map_err(|error| DhttpError::from_error("home.load_identity", error))
    }

    pub async fn identity_exists(&self, name: &str) -> Result<bool> {
        let name = parse_name("home.identity_exists", name)?;
        Ok(self.0.identity_exists(name).await)
    }

    pub async fn identities(&self) -> Result<Vec<String>> {
        let mut identities: Vec<_> = self
            .0
            .identities()
            .map_ok(|name| name.to_string())
            .try_collect()
            .await
            .map_err(|error| DhttpError::from_error("home.identities", error))?;
        identities.sort();
        Ok(identities)
    }
}

impl AsRef<dhttp::home::DhttpHome> for Home {
    fn as_ref(&self) -> &dhttp::home::DhttpHome {
        &self.0
    }
}

impl From<dhttp::home::DhttpHome> for Home {
    fn from(home: dhttp::home::DhttpHome) -> Self {
        Self(home)
    }
}

impl From<Home> for dhttp::home::DhttpHome {
    fn from(home: Home) -> Self {
        home.0
    }
}

impl IdentityHome {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        dhttp::home::identity::IdentityHome::try_from(path.into())
            .map(Self)
            .map_err(|error| DhttpError::from_error("identity_home.from_path", error))
    }

    pub fn name(&self) -> String {
        self.0.name().to_string()
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub async fn identity(&self) -> Result<Identity> {
        self.0
            .identity()
            .await
            .map(Identity::from)
            .map_err(|error| DhttpError::from_error("identity_home.identity", error))
    }
}

impl AsRef<dhttp::home::identity::IdentityHome> for IdentityHome {
    fn as_ref(&self) -> &dhttp::home::identity::IdentityHome {
        &self.0
    }
}

impl From<dhttp::home::identity::IdentityHome> for IdentityHome {
    fn from(home: dhttp::home::identity::IdentityHome) -> Self {
        Self(home)
    }
}

impl From<IdentityHome> for dhttp::home::identity::IdentityHome {
    fn from(home: IdentityHome) -> Self {
        home.0
    }
}

fn parse_name(operation: &'static str, name: &str) -> Result<dhttp::name::DhttpName<'static>> {
    dhttp::name::DhttpName::parse(name).map_err(|error| DhttpError::from_error(operation, error))
}
