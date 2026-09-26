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
mod tests {
    use super::*;
    #[test]
    fn subject_is_the_canonical_textual_owner_hash() {
        let certificate = qtls::CertificateDer::from(
            include_bytes!("../../identity/tests/fixtures/valid.der").as_slice(),
        );
        assert_eq!(
            subject_id(&[certificate]).unwrap(),
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(subject_id(&[]).is_err());
        assert!(subject_id(&[qtls::CertificateDer::from(b"invalid".as_slice())]).is_err());
    }
    #[test]
    fn canonical_signatures_verify_and_detect_modified_messages() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["signer.dhttp.net".to_owned()]).unwrap();
        let authority = qtls::LocalAuthority::new(
            &qtls::default_provider(),
            Arc::from("signer.dhttp.net"),
            vec![generated.cert.der().clone()],
            qtls::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
            vec![1],
        )
        .unwrap();
        let signature = sign(&authority, b"message").unwrap();
        assert!(verify_signature(authority.public_key().as_ref(), b"message", &signature).unwrap());
        assert!(
            !verify_signature(authority.public_key().as_ref(), b"different", &signature).unwrap()
        );
        assert!(verify_signature(b"invalid", b"message", &signature).is_err());
    }
}
