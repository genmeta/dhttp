use std::path::PathBuf;

use futures::TryStreamExt;

use crate::{error::DhttpError, identity::Identity};

type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Debug, Clone)]
pub struct Home(dhttp::config::DhttpConfig);

#[derive(Debug, Clone)]
pub struct IdentityHome(dhttp::config::identity::IdentityConfig);

impl Home {
    pub fn load() -> Result<Self> {
        dhttp::config::DhttpConfig::load_from_environment()
            .map(Self)
            .map_err(|error| DhttpError::from_error("home.load", error))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(dhttp::config::DhttpConfig::new(path.into()))
    }

    pub fn path(&self) -> PathBuf {
        self.0.as_path().to_path_buf()
    }

    pub fn identity_home(&self, name: &str) -> Result<IdentityHome> {
        let name = parse_name("home.identity_home", name)?;
        Ok(IdentityHome(self.0.identity_config(name)))
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

impl AsRef<dhttp::config::DhttpConfig> for Home {
    fn as_ref(&self) -> &dhttp::config::DhttpConfig {
        &self.0
    }
}

impl From<dhttp::config::DhttpConfig> for Home {
    fn from(home: dhttp::config::DhttpConfig) -> Self {
        Self(home)
    }
}

impl From<Home> for dhttp::config::DhttpConfig {
    fn from(home: Home) -> Self {
        home.0
    }
}

impl IdentityHome {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        dhttp::config::identity::IdentityConfig::try_from(path.into())
            .map(Self)
            .map_err(|error| DhttpError::from_error("identity_home.from_path", error))
    }

    pub fn name(&self) -> String {
        self.0.name().to_string()
    }

    pub fn path(&self) -> PathBuf {
        self.0.path().to_path_buf()
    }

    pub async fn identity(&self) -> Result<Identity> {
        self.0
            .identity()
            .await
            .map(Identity::from)
            .map_err(|error| DhttpError::from_error("identity_home.identity", error))
    }
}

impl AsRef<dhttp::config::identity::IdentityConfig> for IdentityHome {
    fn as_ref(&self) -> &dhttp::config::identity::IdentityConfig {
        &self.0
    }
}

impl From<dhttp::config::identity::IdentityConfig> for IdentityHome {
    fn from(home: dhttp::config::identity::IdentityConfig) -> Self {
        Self(home)
    }
}

impl From<IdentityHome> for dhttp::config::identity::IdentityConfig {
    fn from(home: IdentityHome) -> Self {
        home.0
    }
}

fn parse_name(operation: &'static str, name: &str) -> Result<dhttp::name::DhttpName<'static>> {
    name.parse::<dhttp::name::DhttpName>()
        .map_err(|error| DhttpError::from_error(operation, error))
}
