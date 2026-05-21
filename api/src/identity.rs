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
