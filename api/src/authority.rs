use std::sync::Arc;

use dhttp::identity::{
    LocalAuthority as CoreLocalAuthority, RemoteAuthority as CoreRemoteAuthority,
    SignError as CoreSignError, VerifyError as CoreVerifyError,
};

use crate::error::DhttpError;

pub type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Clone)]
pub struct LocalAuthority {
    inner: Arc<dyn CoreLocalAuthority>,
}

impl LocalAuthority {
    pub fn new(inner: Arc<dyn CoreLocalAuthority>) -> Self {
        Self { inner }
    }

    pub fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner
            .cert_chain()
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key().as_ref().to_vec()
    }

    pub async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.inner
            .sign(&data)
            .await
            .map_err(|error: CoreSignError| DhttpError::from_error("local_authority.sign", error))
    }

    pub async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        self.inner
            .verify(&data, &signature)
            .await
            .map_err(|error: CoreVerifyError| {
                DhttpError::from_error("local_authority.verify", error)
            })
    }
}

#[derive(Clone)]
pub struct RemoteAuthority {
    inner: Arc<dyn CoreRemoteAuthority>,
}

impl RemoteAuthority {
    pub fn new(inner: Arc<dyn CoreRemoteAuthority>) -> Self {
        Self { inner }
    }

    pub fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner
            .cert_chain()
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key().as_ref().to_vec()
    }

    pub async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        self.inner
            .verify(&data, &signature)
            .await
            .map_err(|error: CoreVerifyError| {
                DhttpError::from_error("remote_authority.verify", error)
            })
    }
}

impl From<dhttp::identity::Identity> for LocalAuthority {
    fn from(identity: dhttp::identity::Identity) -> Self {
        Self::new(Arc::new(identity))
    }
}

impl From<dhttp::identity::Identity> for RemoteAuthority {
    fn from(identity: dhttp::identity::Identity) -> Self {
        Self::new(Arc::new(identity))
    }
}
