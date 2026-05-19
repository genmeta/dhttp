use std::sync::Arc;

use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer},
};
use snafu::{ResultExt, Snafu};
use verify_error::UnsupportedSchemeSnafu as VerifyUnsupportedScheme;
use x509_parser::prelude::FromDer;

use crate::name::Name;

/// A TLS identity backed by a certificate chain and private key.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub name: Name<'static>,
    pub certs: Arc<Vec<CertificateDer<'static>>>,
    pub key: Arc<PrivateKeyDer<'static>>,
    pub ocsp: Arc<Option<Vec<u8>>>,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignError {
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(display("cryptographic operation failed"))]
    Crypto { source: rustls::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum VerifyError {
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
}

impl Identity {
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

    pub fn name(&self) -> &Name<'static> {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }

    pub fn certs(&self) -> &[CertificateDer<'static>] {
        self.cert_chain()
    }

    pub fn key(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }

    pub fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        match x509_parser::certificate::X509Certificate::from_der(&self.certs[0]) {
            Ok((_remain, certificate)) => {
                let spki = certificate.public_key().raw;
                spki.to_owned().into()
            }
            Err(_) if self.certs.len() == 1 => self.certs[0].as_ref().into(),
            Err(_) => unreachable!("rustls returned an invalid peer_certificates"),
        }
    }

    pub fn sign_algorithm(&self) -> Result<rustls::SignatureAlgorithm, SignError> {
        use snafu::ResultExt;
        let key = rustls::crypto::ring::sign::any_supported_type(&self.key)
            .context(sign_error::CryptoSnafu)?;
        Ok(key.algorithm())
    }

    pub fn sign(&self, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let key = rustls::crypto::ring::sign::any_supported_type(&self.key)
            .context(sign_error::CryptoSnafu)?;
        let signer = key
            .choose_scheme(&[scheme])
            .ok_or_else(|| sign_error::UnsupportedSchemeSnafu { scheme }.build())?;
        signer.sign(data).context(sign_error::CryptoSnafu)
    }

    pub fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerifyError> {
        let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
            SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
            SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
            SignatureScheme::ED25519 => &ring::signature::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
            _ => return VerifyUnsupportedScheme { scheme }.fail(),
        };

        let spki = self.public_key();
        let public_key = match x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki) {
            Ok((_remain, spki)) => spki.subject_public_key,
            Err(_) => unreachable!("rustls returned an invalid peer_certificates"),
        };

        Ok(
            ring::signature::UnparsedPublicKey::new(algorithm, public_key)
                .verify(data, signature)
                .is_ok(),
        )
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
