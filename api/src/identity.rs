#[derive(Debug, Clone, PartialEq)]
pub struct Identity(dhttp::identity::Identity);

impl Identity {
    pub fn name(&self) -> String {
        self.0.name().as_str().to_owned()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.0
            .cert_chain()
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        if self.0.cert_chain().is_empty() {
            return Vec::new();
        }
        self.0.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, scheme: u16, data: &[u8]) -> Result<Vec<u8>, crate::error::DhttpError> {
        let scheme = rustls::SignatureScheme::from(scheme);
        self.0
            .sign(scheme, data)
            .map_err(|error| crate::error::DhttpError::from_error("identity.sign", error))
    }

    pub fn verify(
        &self,
        scheme: u16,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::error::DhttpError> {
        let scheme = rustls::SignatureScheme::from(scheme);
        self.0
            .verify(scheme, data, signature)
            .map_err(|error| crate::error::DhttpError::from_error("identity.verify", error))
    }

    pub fn as_local_authority(&self) -> crate::authority::LocalAuthority {
        crate::authority::LocalAuthority::from(self.0.clone())
    }

    pub fn as_remote_authority(&self) -> crate::authority::RemoteAuthority {
        crate::authority::RemoteAuthority::from(self.0.clone())
    }
}

impl AsRef<dhttp::identity::Identity> for Identity {
    fn as_ref(&self) -> &dhttp::identity::Identity {
        &self.0
    }
}

impl From<dhttp::identity::Identity> for Identity {
    fn from(identity: dhttp::identity::Identity) -> Self {
        Self(identity)
    }
}

impl From<Identity> for dhttp::identity::Identity {
    fn from(identity: Identity) -> Self {
        identity.0
    }
}
