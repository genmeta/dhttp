use std::sync::Arc;

use futures::future::BoxFuture;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer},
};
use snafu::{OptionExt, ResultExt, Snafu};
use x509_parser::prelude::FromDer;
use x509_parser::{
    extensions::ParsedExtension,
    oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
        OID_SIG_ED25519,
    },
    x509::SubjectPublicKeyInfo,
};

use crate::{certificate::DhttpSubjectKeyIdentifier, name::Name};

const RSA_CANONICAL_SCHEME: SignatureScheme = SignatureScheme::RSA_PSS_SHA512;
const ECDSA_CANONICAL_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
];
const ED25519_CANONICAL_SCHEME: SignatureScheme = SignatureScheme::ED25519;

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
pub enum ExtractSubjectKeyIdentifierError {
    #[snafu(display("certificate chain is empty"))]
    EmptyCertificateChain,
    #[snafu(display("failed to parse leaf certificate"))]
    ParseCertificate {
        source: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },
    #[snafu(display("failed to parse subject key identifier extension"))]
    ParseExtension,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ExtractDhttpSubjectKeyIdentifierError {
    #[snafu(transparent)]
    ExtractSubjectKeyIdentifier {
        source: ExtractSubjectKeyIdentifierError,
    },
    #[snafu(display("leaf certificate is missing subject key identifier"))]
    MissingSubjectKeyIdentifier,
    #[snafu(display("subject key identifier is not a dhttp subject key identifier"))]
    InvalidDhttpSubjectKeyIdentifier {
        source: crate::certificate::InvalidDhttpSubjectKeyIdentifier,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignError {
    #[snafu(display("unsupported signing key type"))]
    UnsupportedKey,
    #[snafu(display("cryptographic operation failed"))]
    Crypto { source: rustls::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum VerifyError {
    #[snafu(display("unsupported public key type"))]
    UnsupportedKey,
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

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let key = rustls::crypto::ring::sign::any_supported_type(&self.key)
            .context(sign_error::CryptoSnafu)?;
        sign_with_key(key.as_ref(), data)
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
        verify_signature(self.public_key(), data, signature)
    }

    pub fn subject_key_identifier(
        &self,
    ) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError> {
        extract_subject_key_identifier(self.cert_chain())
    }

    pub fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
        extract_dhttp_subject_key_identifier(self.cert_chain())
    }
}

include!("identity/authority.rs");
include!("identity/certificate.rs");
include!("identity/signature.rs");

#[cfg(test)]
#[path = "../tests/unit/identity.rs"]
mod tests;
