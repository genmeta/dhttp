//! Cross-language stable representation of [`rustls::SignatureScheme`].
//!
//! The wire-level contract uses IANA TLS SignatureScheme numbers (u16). Bindings
//! also accept the rustls constant name (case-insensitive) as a convenience for
//! callers who prefer string identifiers.

use rustls::SignatureScheme;
use snafu::Snafu;

/// IANA TLS SignatureScheme numeric values currently supported by
/// [`dhttp_identity`]'s sign/verify paths.
///
/// These mirror the variants matched in `dhttp_identity::identity::verify_signature`.
/// New entries must be added in lock-step with the verifier.
pub mod codes {
    pub const ECDSA_NISTP384_SHA384: u16 = 0x0503;
    pub const ECDSA_NISTP256_SHA256: u16 = 0x0403;
    pub const ED25519: u16 = 0x0807;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const RSA_PSS_SHA256: u16 = 0x0804;
    pub const RSA_PSS_SHA384: u16 = 0x0805;
    pub const RSA_PSS_SHA512: u16 = 0x0806;
}

/// Convert an IANA TLS SignatureScheme number into the rustls enum.
///
/// Unknown values pass through as [`SignatureScheme::Unknown`]; the downstream
/// rustls signer/verifier will reject them with a typed error, which is the
/// behaviour we want — no allow-list duplication in the binding layer.
pub fn from_u16(value: u16) -> SignatureScheme {
    SignatureScheme::from(value)
}

pub fn to_u16(scheme: SignatureScheme) -> u16 {
    u16::from(scheme)
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseNameError {
    #[snafu(display("unknown signature scheme name {name:?}"))]
    UnknownName { name: String },
}

/// Parse a rustls SignatureScheme constant name (case-insensitive) into the
/// IANA numeric form. Only names corresponding to schemes that
/// [`dhttp_identity::identity::verify_signature`] supports are accepted; this
/// keeps the string surface aligned with the active verification matrix and
/// avoids exposing IETF-deprecated schemes by name.
pub fn parse_name(name: &str) -> Result<u16, ParseNameError> {
    let normalized = name.trim().to_ascii_uppercase();
    let code = match normalized.as_str() {
        "ECDSA_NISTP384_SHA384" => codes::ECDSA_NISTP384_SHA384,
        "ECDSA_NISTP256_SHA256" => codes::ECDSA_NISTP256_SHA256,
        "ED25519" => codes::ED25519,
        "RSA_PKCS1_SHA256" => codes::RSA_PKCS1_SHA256,
        "RSA_PKCS1_SHA384" => codes::RSA_PKCS1_SHA384,
        "RSA_PKCS1_SHA512" => codes::RSA_PKCS1_SHA512,
        "RSA_PSS_SHA256" => codes::RSA_PSS_SHA256,
        "RSA_PSS_SHA384" => codes::RSA_PSS_SHA384,
        "RSA_PSS_SHA512" => codes::RSA_PSS_SHA512,
        _ => {
            return parse_name_error::UnknownNameSnafu {
                name: name.to_owned(),
            }
            .fail();
        }
    };
    Ok(code)
}
