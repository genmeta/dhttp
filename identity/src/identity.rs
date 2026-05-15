use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::name::Name;

/// A TLS identity backed by a certificate chain and private key.
///
/// All fields are public — this is a pure data bag with no accessor methods.
/// Fields use `Arc` for cheap cloning and sharing across threads.
/// This is the canonical identity type for DHttp endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub name: Name<'static>,
    pub certs: Arc<Vec<CertificateDer<'static>>>,
    pub key: Arc<PrivateKeyDer<'static>>,
    pub ocsp: Arc<Option<Vec<u8>>>,
}

impl Identity {
    /// Construct a new identity from its components.
    ///
    /// `ocsp` defaults to `Arc::new(None)` — call [`set_ocsp`](Self::set_ocsp)
    /// if an OCSP response is available.
    pub fn new(
        name: Name<'static>,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            name,
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use crate::Identity;
    use crate::name::Name;

    fn dummy_name() -> Name<'static> {
        "test.example.com".parse().unwrap()
    }

    fn dummy_certs() -> Vec<CertificateDer<'static>> {
        Vec::new()
    }

    fn dummy_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())
    }

    #[test]
    fn construct_identity() {
        let id = Identity::new(dummy_name(), dummy_certs(), dummy_key());
        assert_eq!(&id.name, &"test.example.com".parse::<Name>().unwrap());
        assert!(id.certs.is_empty());
    }

    #[test]
    fn clone_shares_certs_via_arc() {
        let id = Identity::new(dummy_name(), dummy_certs(), dummy_key());
        let cloned = id.clone();
        assert!(Arc::ptr_eq(&id.certs, &cloned.certs));
    }

    #[test]
    fn clone_shares_key_via_arc() {
        let id = Identity::new(dummy_name(), dummy_certs(), dummy_key());
        let cloned = id.clone();
        assert!(Arc::ptr_eq(&id.key, &cloned.key));
    }

    #[test]
    fn ocsp_defaults_to_none() {
        let id = Identity::new(dummy_name(), dummy_certs(), dummy_key());
        assert!(id.ocsp.is_none());
    }
}
