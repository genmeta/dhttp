//! DHTTP certificate extraction and canonical signature verification.

use rustls::{SignatureScheme, pki_types::CertificateDer};
use snafu::{OptionExt, ResultExt, Snafu};
use x509_parser::{
    extensions::ParsedExtension,
    oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
        OID_SIG_ED25519,
    },
    prelude::FromDer,
    x509::SubjectPublicKeyInfo,
};

use super::{DhttpSubjectKeyIdentifier, InvalidDhttpSubjectKeyIdentifier};

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
        source: InvalidDhttpSubjectKeyIdentifier,
    },
}

#[derive(Debug, Snafu)]
pub enum VerifyError {
    #[snafu(display("unsupported public key type"))]
    UnsupportedKey,
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

/// Verify with the DHTTP canonical algorithm selected by the public key.
pub fn verify_signature(spki: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    let scheme = canonical_verification_scheme(spki)?;
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return Err(VerifyError::UnsupportedKey),
    };

    let public_key = match SubjectPublicKeyInfo::from_der(spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_) => return Err(VerifyError::UnsupportedKey),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}

fn canonical_verification_scheme(spki: &[u8]) -> Result<SignatureScheme, VerifyError> {
    let Ok((_remain, spki)) = SubjectPublicKeyInfo::from_der(spki) else {
        return Err(VerifyError::UnsupportedKey);
    };

    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        return Ok(SignatureScheme::ED25519);
    }
    if spki.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
        return Ok(SignatureScheme::RSA_PSS_SHA512);
    }
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(VerifyError::UnsupportedKey);
    }

    let Some(curve) = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
    else {
        return Err(VerifyError::UnsupportedKey);
    };

    if curve == OID_EC_P256 {
        Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
    } else if curve == OID_NIST_EC_P384 {
        Ok(SignatureScheme::ECDSA_NISTP384_SHA384)
    } else {
        Err(VerifyError::UnsupportedKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_validates_dhttp_ski() {
        let valid =
            CertificateDer::from(include_bytes!("../../tests/fixtures/valid.der").as_slice());
        let ski = extract_dhttp_subject_key_identifier(&[valid]).unwrap();
        assert_eq!(ski.chain().sequence().get(), 0);
        assert_eq!(
            ski.owner_hash().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let missing =
            CertificateDer::from(include_bytes!("../../tests/fixtures/missing.der").as_slice());
        assert!(matches!(
            extract_dhttp_subject_key_identifier(&[missing]),
            Err(ExtractDhttpSubjectKeyIdentifierError::MissingSubjectKeyIdentifier)
        ));

        let malformed =
            CertificateDer::from(include_bytes!("../../tests/fixtures/malformed.der").as_slice());
        assert!(matches!(
            extract_dhttp_subject_key_identifier(&[malformed]),
            Err(ExtractDhttpSubjectKeyIdentifierError::InvalidDhttpSubjectKeyIdentifier { .. })
        ));
    }
}
