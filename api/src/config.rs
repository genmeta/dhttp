use std::path::PathBuf;

use futures::TryStreamExt;

use crate::{error::DhttpError, identity::Identity};

type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Debug, Clone)]
pub struct Config(dhttp::config::DhttpConfig);

#[derive(Debug, Clone)]
pub struct IdentityConfig(dhttp::config::identity::IdentityConfig);

impl Config {
    pub fn load() -> Result<Self> {
        dhttp::config::DhttpConfig::load_from_environment()
            .map(Self)
            .map_err(|error| DhttpError::from_error("config.load", error))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(dhttp::config::DhttpConfig::new(path.into()))
    }

    pub fn path(&self) -> PathBuf {
        self.0.as_path().to_path_buf()
    }

    pub fn identity_config(&self, name: &str) -> Result<IdentityConfig> {
        let name = parse_name("config.identity_config", name)?;
        Ok(IdentityConfig(self.0.identity_config(name)))
    }

    pub async fn load_identity(&self, name: &str) -> Result<IdentityConfig> {
        let name = parse_name("config.load_identity", name)?;
        self.0
            .load_identity(name)
            .await
            .map(IdentityConfig)
            .map_err(|error| DhttpError::from_error("config.load_identity", error))
    }

    pub async fn identity_exists(&self, name: &str) -> Result<bool> {
        let name = parse_name("config.identity_exists", name)?;
        Ok(self.0.identity_exists(name).await)
    }

    pub async fn identities(&self) -> Result<Vec<String>> {
        let mut identities: Vec<_> = self
            .0
            .identities()
            .map_ok(|name| name.to_string())
            .try_collect()
            .await
            .map_err(|error| DhttpError::from_error("config.identities", error))?;
        identities.sort();
        Ok(identities)
    }
}

impl AsRef<dhttp::config::DhttpConfig> for Config {
    fn as_ref(&self) -> &dhttp::config::DhttpConfig {
        &self.0
    }
}

impl From<dhttp::config::DhttpConfig> for Config {
    fn from(config: dhttp::config::DhttpConfig) -> Self {
        Self(config)
    }
}

impl From<Config> for dhttp::config::DhttpConfig {
    fn from(config: Config) -> Self {
        config.0
    }
}

impl IdentityConfig {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        dhttp::config::identity::IdentityConfig::try_from(path.into())
            .map(Self)
            .map_err(|error| DhttpError::from_error("identity_config.from_path", error))
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
            .map_err(|error| DhttpError::from_error("identity_config.identity", error))
    }
}

impl AsRef<dhttp::config::identity::IdentityConfig> for IdentityConfig {
    fn as_ref(&self) -> &dhttp::config::identity::IdentityConfig {
        &self.0
    }
}

impl From<dhttp::config::identity::IdentityConfig> for IdentityConfig {
    fn from(config: dhttp::config::identity::IdentityConfig) -> Self {
        Self(config)
    }
}

impl From<IdentityConfig> for dhttp::config::identity::IdentityConfig {
    fn from(config: IdentityConfig) -> Self {
        config.0
    }
}

fn parse_name(operation: &'static str, name: &str) -> Result<dhttp::name::DhttpName<'static>> {
    name.parse::<dhttp::name::DhttpName>()
        .map_err(|error| DhttpError::from_error(operation, error))
}
