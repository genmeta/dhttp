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

/// Local authority for DHTTP identity material.
///
/// Signatures use DHTTP's canonical key-to-signature-scheme policy instead of
/// accepting a caller-supplied scheme. The policy is:
///
/// - Ed25519 keys use [`SignatureScheme::ED25519`].
/// - ECDSA P-256 keys use [`SignatureScheme::ECDSA_NISTP256_SHA256`].
/// - ECDSA P-384 keys use [`SignatureScheme::ECDSA_NISTP384_SHA384`].
/// - RSA keys use [`SignatureScheme::RSA_PSS_SHA512`], matching the QUIC/TLS
///   RSA signing preference used by rustls.
///
/// Callers should treat `sign` and `verify` as DHTTP identity operations, not
/// as general-purpose cryptographic primitives with negotiable algorithms.
pub trait LocalAuthority: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>>;

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), data, signature);
        Box::pin(std::future::ready(result))
    }
}

/// Remote authority for DHTTP identity material.
///
/// Verification uses the same DHTTP canonical key-to-signature-scheme policy
/// as [`LocalAuthority`]. The policy is:
///
/// - Ed25519 keys use [`SignatureScheme::ED25519`].
/// - ECDSA P-256 keys use [`SignatureScheme::ECDSA_NISTP256_SHA256`].
/// - ECDSA P-384 keys use [`SignatureScheme::ECDSA_NISTP384_SHA384`].
/// - RSA keys use [`SignatureScheme::RSA_PSS_SHA512`], matching the QUIC/TLS
///   RSA signing preference used by rustls.
///
/// A remote authority does not carry an explicit signature scheme in its API;
/// the scheme is derived from the authority public key according to the
/// documented DHTTP policy.
pub trait RemoteAuthority: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), data, signature);
        Box::pin(std::future::ready(result))
    }
}

pub fn extract_subject_key_identifier<'a>(
    cert_chain: &'a [CertificateDer<'a>],
) -> Result<Option<&'a [u8]>, ExtractSubjectKeyIdentifierError> {
    let leaf = cert_chain
        .first()
        .context(extract_subject_key_identifier_error::EmptyCertificateChainSnafu)?;
    let (_remain, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf)
        .context(extract_subject_key_identifier_error::ParseCertificateSnafu)?;

    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            return Ok(Some(identifier.0));
        }
        if extension.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
            return extract_subject_key_identifier_error::ParseExtensionSnafu.fail();
        }
    }

    Ok(None)
}

pub fn extract_dhttp_subject_key_identifier(
    cert_chain: &[CertificateDer<'_>],
) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
    let ski = extract_subject_key_identifier(cert_chain)?
        .context(extract_dhttp_subject_key_identifier_error::MissingSubjectKeyIdentifierSnafu)?;
    DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(ski)
        .context(extract_dhttp_subject_key_identifier_error::InvalidDhttpSubjectKeyIdentifierSnafu)
}

mod private {
    pub trait Sealed {}

    impl<T: ?Sized> Sealed for T {}
}

pub trait LocalAuthorityCertificateExt: private::Sealed {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError>;

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError>;
}

impl<T: ?Sized + LocalAuthority> LocalAuthorityCertificateExt for T {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError> {
        extract_subject_key_identifier(self.cert_chain())
    }

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
        extract_dhttp_subject_key_identifier(self.cert_chain())
    }
}

pub trait RemoteAuthorityCertificateExt: private::Sealed {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError>;

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError>;
}

impl<T: ?Sized + RemoteAuthority> RemoteAuthorityCertificateExt for T {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError> {
        extract_subject_key_identifier(self.cert_chain())
    }

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
        extract_dhttp_subject_key_identifier(self.cert_chain())
    }
}

pub fn extract_public_key<'d>(cert_chain: &'d [CertificateDer<'d>]) -> SubjectPublicKeyInfoDer<'d> {
    match x509_parser::certificate::X509Certificate::from_der(&cert_chain[0]) {
        Ok((_remain, certificate)) => {
            let spki = certificate.public_key().raw;
            spki.to_owned().into()
        }
        Err(_) if cert_chain.len() == 1 => cert_chain[0].as_ref().into(),
        Err(_) => unreachable!("rustls returned an invalid peer_certificates"),
    }
}

pub fn sign_with_key(
    key: &(impl rustls::sign::SigningKey + ?Sized),
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    for scheme in canonical_signing_schemes(key.algorithm()) {
        if let Some(signer) = key.choose_scheme(&[*scheme]) {
            return signer.sign(data).context(sign_error::CryptoSnafu);
        }
    }

    sign_error::UnsupportedKeySnafu.fail()
}

pub fn verify_signature(
    spki: SubjectPublicKeyInfoDer,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let scheme = canonical_verification_scheme(spki.as_ref())?;
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return verify_error::UnsupportedKeySnafu.fail(),
    };

    let public_key = match SubjectPublicKeyInfo::from_der(&spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_) => return verify_error::UnsupportedKeySnafu.fail(),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}

fn canonical_signing_schemes(algorithm: rustls::SignatureAlgorithm) -> &'static [SignatureScheme] {
    match algorithm {
        rustls::SignatureAlgorithm::RSA => &[RSA_CANONICAL_SCHEME],
        rustls::SignatureAlgorithm::ECDSA => ECDSA_CANONICAL_SCHEMES,
        rustls::SignatureAlgorithm::ED25519 => &[ED25519_CANONICAL_SCHEME],
        _ => &[],
    }
}

fn canonical_verification_scheme(spki: &[u8]) -> Result<SignatureScheme, VerifyError> {
    let Ok((_remain, spki)) = SubjectPublicKeyInfo::from_der(spki) else {
        return verify_error::UnsupportedKeySnafu.fail();
    };

    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        return Ok(ED25519_CANONICAL_SCHEME);
    }

    if spki.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
        return Ok(RSA_CANONICAL_SCHEME);
    }

    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return verify_error::UnsupportedKeySnafu.fail();
    }

    let Some(curve) = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
    else {
        return verify_error::UnsupportedKeySnafu.fail();
    };

    if curve == OID_EC_P256 {
        Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
    } else if curve == OID_NIST_EC_P384 {
        Ok(SignatureScheme::ECDSA_NISTP384_SHA384)
    } else {
        verify_error::UnsupportedKeySnafu.fail()
    }
}

impl LocalAuthority for Identity {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        self.cert_chain()
    }

    fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
        let result = Identity::sign(self, data);
        Box::pin(std::future::ready(result))
    }
}

impl RemoteAuthority for Identity {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        self.cert_chain()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ring::signature::KeyPair;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::sign::{Signer, SigningKey};
    use rustls::{SignatureAlgorithm, SignatureScheme};

    use crate::certificate::CertificateUsage;
    use crate::identity::{Identity, LocalAuthorityCertificateExt, RemoteAuthorityCertificateExt};
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

    fn fixture_identity(name: &str, der: &'static [u8]) -> Identity {
        Identity::new(
            name.parse().unwrap(),
            vec![CertificateDer::from(der.to_vec())],
            dummy_key(),
        )
    }

    fn valid_dhttp_ski_identity() -> Identity {
        fixture_identity(
            "client.example.com.dhttp.net",
            include_bytes!("../tests/fixtures/valid.der"),
        )
    }

    fn ed25519_identity() -> Identity {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        spki.extend_from_slice(keypair.public_key().as_ref());

        Identity::new(
            dummy_name(),
            vec![CertificateDer::from(spki)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())),
        )
    }

    #[derive(Debug)]
    struct RsaPssSha512OnlyKey;

    #[derive(Debug)]
    struct RsaPssSha512Signer;

    impl SigningKey for RsaPssSha512OnlyKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::RSA_PSS_SHA512)
                .then(|| Box::new(RsaPssSha512Signer) as Box<dyn Signer>)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::RSA
        }
    }

    impl Signer for RsaPssSha512Signer {
        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            Ok(b"rsa-pss-sha512".to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::RSA_PSS_SHA512
        }
    }

    fn rsa_subject_public_key_info() -> Vec<u8> {
        vec![
            0x30, 0x12, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x05, 0x00, 0x03, 0x01, 0x00,
        ]
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

    #[test]
    fn identity_is_async_authority() {
        fn assert_local_authority<T: crate::identity::LocalAuthority>() {}
        fn assert_remote_authority<T: crate::identity::RemoteAuthority>() {}

        assert_local_authority::<Identity>();
        assert_remote_authority::<Identity>();
    }

    #[test]
    fn rsa_canonical_scheme_matches_quic_tls_preference() {
        assert_eq!(
            super::sign_with_key(&RsaPssSha512OnlyKey, b"payload")
                .expect("rsa canonical signature"),
            b"rsa-pss-sha512"
        );
        assert_eq!(
            super::canonical_verification_scheme(&rsa_subject_public_key_info())
                .expect("rsa canonical verification scheme"),
            SignatureScheme::RSA_PSS_SHA512
        );
    }

    #[test]
    fn identity_signs_and_verifies_with_canonical_scheme() {
        let identity = ed25519_identity();
        let signature = identity.sign(b"payload").expect("canonical signature");

        assert!(
            identity
                .verify(b"payload", &signature)
                .expect("canonical verification")
        );
        assert!(
            !identity
                .verify(b"wrong payload", &signature)
                .expect("canonical verification")
        );
    }

    #[test]
    fn identity_extracts_dhttp_subject_key_identifier() {
        let identity = valid_dhttp_ski_identity();
        let raw = identity
            .subject_key_identifier()
            .expect("extract raw ski")
            .expect("fixture has ski");

        assert_eq!(
            raw,
            b"0:0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let dhttp = identity
            .dhttp_subject_key_identifier()
            .expect("extract dhttp ski");
        assert_eq!(dhttp.chain().usage(), CertificateUsage::ClientOnly);
        assert_eq!(dhttp.chain().sequence().get(), 0);
    }

    #[test]
    fn identity_reports_missing_subject_key_identifier() {
        let identity = fixture_identity(
            "missing.example.com.dhttp.net",
            include_bytes!("../tests/fixtures/missing.der"),
        );

        assert!(identity.subject_key_identifier().unwrap().is_none());
        assert!(matches!(
            identity.dhttp_subject_key_identifier().unwrap_err(),
            super::ExtractDhttpSubjectKeyIdentifierError::MissingSubjectKeyIdentifier
        ));
    }

    #[test]
    fn identity_reports_malformed_dhttp_subject_key_identifier() {
        let identity = fixture_identity(
            "malformed.example.com.dhttp.net",
            include_bytes!("../tests/fixtures/malformed.der"),
        );

        assert!(matches!(
            identity.dhttp_subject_key_identifier().unwrap_err(),
            super::ExtractDhttpSubjectKeyIdentifierError::InvalidDhttpSubjectKeyIdentifier { .. }
        ));
    }

    #[test]
    fn authority_extension_traits_extract_dhttp_subject_key_identifier() {
        let identity = valid_dhttp_ski_identity();

        let local = LocalAuthorityCertificateExt::dhttp_subject_key_identifier(&identity)
            .expect("local authority dhttp ski");
        let remote = RemoteAuthorityCertificateExt::dhttp_subject_key_identifier(&identity)
            .expect("remote authority dhttp ski");

        assert_eq!(local, remote);
    }

    #[test]
    fn authority_traits_do_not_require_signature_scheme() {
        let identity = ed25519_identity();
        let signature = futures::executor::block_on(crate::identity::LocalAuthority::sign(
            &identity, b"payload",
        ))
        .expect("canonical authority signature");

        assert!(
            futures::executor::block_on(crate::identity::LocalAuthority::verify(
                &identity, b"payload", &signature,
            ))
            .expect("canonical local authority verification")
        );
        assert!(
            futures::executor::block_on(crate::identity::RemoteAuthority::verify(
                &identity, b"payload", &signature,
            ))
            .expect("canonical remote authority verification")
        );
    }
}
