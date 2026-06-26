use std::path::PathBuf;

use futures::TryStreamExt;

use crate::{error::DhttpError, identity::Identity};

type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Debug, Clone)]
pub struct DhttpHome(dhttp::home::DhttpHome);

#[derive(Debug, Clone)]
pub struct IdentityProfile(dhttp::home::identity::IdentityProfile);

impl DhttpHome {
    pub fn load() -> Result<Self> {
        dhttp::home::DhttpHome::load(dhttp::home::HomeScope::User)
            .map(Self)
            .map_err(|error| DhttpError::from_error("home.load", error))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(dhttp::home::DhttpHome::new(path.into()))
    }

    pub fn path(&self) -> PathBuf {
        self.0.as_path().to_path_buf()
    }

    pub fn identity_profile(&self, name: &str) -> Result<IdentityProfile> {
        let name = parse_name("home.identity_profile", name)?;
        Ok(IdentityProfile(self.0.identity_profile(name)))
    }

    pub async fn resolve_identity_profile(&self, name: &str) -> Result<IdentityProfile> {
        let name = parse_name("home.resolve_identity_profile", name)?;
        self.0
            .resolve_identity_profile(name)
            .await
            .map(IdentityProfile)
            .map_err(|error| DhttpError::from_error("home.resolve_identity_profile", error))
    }

    pub async fn identity_profile_exists(&self, name: &str) -> Result<bool> {
        let name = parse_name("home.identity_profile_exists", name)?;
        Ok(self.0.identity_profile_exists(name).await)
    }

    pub async fn identity_profile_names(&self) -> Result<Vec<String>> {
        let mut names: Vec<_> = self
            .0
            .identity_profile_names()
            .map_ok(|name| name.to_string())
            .try_collect()
            .await
            .map_err(|error| DhttpError::from_error("home.identity_profile_names", error))?;
        names.sort();
        Ok(names)
    }
}

impl AsRef<dhttp::home::DhttpHome> for DhttpHome {
    fn as_ref(&self) -> &dhttp::home::DhttpHome {
        &self.0
    }
}

impl From<dhttp::home::DhttpHome> for DhttpHome {
    fn from(home: dhttp::home::DhttpHome) -> Self {
        Self(home)
    }
}

impl From<DhttpHome> for dhttp::home::DhttpHome {
    fn from(home: DhttpHome) -> Self {
        home.0
    }
}

impl IdentityProfile {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        dhttp::home::identity::IdentityProfile::try_from(path.into())
            .map(Self)
            .map_err(|error| DhttpError::from_error("identity_profile.from_path", error))
    }

    pub fn name(&self) -> String {
        self.0.name().to_string()
    }

    pub fn path(&self) -> PathBuf {
        self.0.path().to_path_buf()
    }

    pub async fn load_identity(&self) -> Result<Identity> {
        self.0
            .load_identity()
            .await
            .map(Identity::from)
            .map_err(|error| DhttpError::from_error("identity_profile.load_identity", error))
    }
}

impl AsRef<dhttp::home::identity::IdentityProfile> for IdentityProfile {
    fn as_ref(&self) -> &dhttp::home::identity::IdentityProfile {
        &self.0
    }
}

impl From<dhttp::home::identity::IdentityProfile> for IdentityProfile {
    fn from(profile: dhttp::home::identity::IdentityProfile) -> Self {
        Self(profile)
    }
}

impl From<IdentityProfile> for dhttp::home::identity::IdentityProfile {
    fn from(profile: IdentityProfile) -> Self {
        profile.0
    }
}

fn parse_name(operation: &'static str, name: &str) -> Result<dhttp::name::DhttpName<'static>> {
    name.parse::<dhttp::name::DhttpName>()
        .map_err(|error| DhttpError::from_error(operation, error))
}
