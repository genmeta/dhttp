//! DHTTP SKI and canonical signature rules, using qtls handshake authorities.
pub use crate::endpoint::resolve_remote;
use crate::{Error, Result};
use std::sync::Arc;

pub fn subject_id(certificates: &[qtls::CertificateDer<'_>]) -> Result<Vec<u8>> {
    dhttp_identity::identity::extract_dhttp_subject_key_identifier(certificates)
        .map(|ski| ski.owner_hash().as_str().as_bytes().to_vec())
        .map_err(|error| Error::Io {
            source: Arc::new(std::io::Error::other(error.to_string())),
        })
}
pub fn sign(local: &qtls::LocalAuthority, data: &[u8]) -> Result<Vec<u8>> {
    // The canonical schemes match the existing DHTTP identity implementation.
    for scheme in [
        qtls::SignatureScheme::RSA_PSS_SHA512,
        qtls::SignatureScheme::ECDSA_NISTP256_SHA256,
        qtls::SignatureScheme::ECDSA_NISTP384_SHA384,
        qtls::SignatureScheme::ED25519,
    ] {
        match local.sign(scheme, data) {
            Ok(signature) => return Ok(signature),
            Err(qtls::SignError::UnsupportedScheme { .. }) => continue,
            Err(error) => {
                return Err(Error::Io {
                    source: Arc::new(std::io::Error::other(error.to_string())),
                });
            }
        }
    }
    Err(Error::InvalidRequest {
        message: "unsupported signing key".into(),
    })
}
pub fn verify_signature(spki: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
    dhttp_identity::identity::verify_signature(spki.into(), data, signature).map_err(|error| {
        Error::Io {
            source: Arc::new(std::io::Error::other(error.to_string())),
        }
    })
}

#[cfg(test)]
#[path = "../tests/unit/certificate.rs"]
mod tests;
