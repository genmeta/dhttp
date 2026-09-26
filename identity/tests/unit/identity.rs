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
        include_bytes!("../fixtures/valid.der"),
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
        0x30, 0x12, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00, 0x03, 0x01, 0x00,
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
        super::sign_with_key(&RsaPssSha512OnlyKey, b"payload").expect("rsa canonical signature"),
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
    assert_eq!(dhttp.chain().usage(), CertificateUsage::ClientAndServer);
    assert_eq!(dhttp.chain().sequence().get(), 0);
}

#[test]
fn identity_reports_missing_subject_key_identifier() {
    let identity = fixture_identity(
        "missing.example.com.dhttp.net",
        include_bytes!("../fixtures/missing.der"),
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
        include_bytes!("../fixtures/malformed.der"),
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
    let signature =
        futures::executor::block_on(crate::identity::LocalAuthority::sign(&identity, b"payload"))
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
