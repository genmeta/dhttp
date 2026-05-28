use std::sync::Arc;

use dhttp::identity::{
    LocalAgent as CoreLocalAgent, RemoteAgent as CoreRemoteAgent, SignError as CoreSignError,
    VerifyError as CoreVerifyError,
};
use rustls::SignatureScheme;

use crate::error::DhttpError;

pub type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Clone)]
pub struct LocalAgent {
    inner: Arc<dyn CoreLocalAgent>,
}

impl LocalAgent {
    pub fn new(inner: Arc<dyn CoreLocalAgent>) -> Self {
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

    pub async fn sign(&self, scheme: u16, data: Vec<u8>) -> Result<Vec<u8>> {
        let scheme = SignatureScheme::from(scheme);
        self.inner
            .sign(scheme, &data)
            .await
            .map_err(|error: CoreSignError| DhttpError::from_error("local_agent.sign", error))
    }

    pub async fn verify(&self, scheme: u16, data: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        let scheme = SignatureScheme::from(scheme);
        self.inner
            .verify(scheme, &data, &signature)
            .await
            .map_err(|error: CoreVerifyError| DhttpError::from_error("local_agent.verify", error))
    }
}

#[derive(Clone)]
pub struct RemoteAgent {
    inner: Arc<dyn CoreRemoteAgent>,
}

impl RemoteAgent {
    pub fn new(inner: Arc<dyn CoreRemoteAgent>) -> Self {
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

    pub async fn verify(&self, scheme: u16, data: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        let scheme = SignatureScheme::from(scheme);
        self.inner
            .verify(scheme, &data, &signature)
            .await
            .map_err(|error: CoreVerifyError| DhttpError::from_error("remote_agent.verify", error))
    }
}

impl From<dhttp::identity::Identity> for LocalAgent {
    fn from(identity: dhttp::identity::Identity) -> Self {
        Self::new(Arc::new(identity))
    }
}

impl From<dhttp::identity::Identity> for RemoteAgent {
    fn from(identity: dhttp::identity::Identity) -> Self {
        Self::new(Arc::new(identity))
    }
}
