use chrono::{DateTime, FixedOffset, Utc};
use dhttp_identity::certificate::CertificateChainKey;
use sha2::{Digest, Sha256};
use snafu::{OptionExt, ResultExt, Snafu};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/// The certificate lifecycle operation that committed material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateAction {
    /// Initial certificate material was committed.
    Apply,
    /// Existing certificate material was renewed.
    Renew,
    /// Existing certificate material was replaced outside renewal.
    Replace,
}

/// One valid UTF-8 issuer organization or common name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateIssuer(String);

impl CertificateIssuer {
    /// Returns the issuer text selected from the leaf certificate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CertificateIssuer {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for CertificateIssuer {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// The leaf certificate's recognized extended key usage category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateUsage {
    /// Extended key usage permits TLS client authentication only.
    ClientOnly,
    /// Extended key usage permits TLS server authentication only.
    ServerOnly,
    /// Extended key usage permits both TLS client and server authentication.
    ClientAndServer,
    /// The leaf has no extended key usage restriction.
    Unrestricted,
    /// Extended key usage is present without client or server authentication.
    Other,
}

/// A SHA-256 digest of the exact leaf DER bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Fingerprint([u8; 32]);

impl Sha256Fingerprint {
    /// Returns the exact 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Fingerprint {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// One certificate lifecycle log record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateLogRecord {
    /// Wall-clock time captured after certificate material was committed.
    pub recorded_at: DateTime<FixedOffset>,
    /// Lifecycle operation that committed the material.
    pub action: CertificateAction,
    /// First valid UTF-8 issuer organization, common name, or missing value.
    pub issuer: Option<CertificateIssuer>,
    /// Leaf extended-key-usage category.
    pub usage: CertificateUsage,
    /// Existing DHTTP certificate chain identity.
    pub chain: CertificateChainKey,
    /// Leaf certificate not-after time.
    pub expires_at: DateTime<FixedOffset>,
    /// SHA-256 digest of the exact leaf DER bytes.
    pub fingerprint: Sha256Fingerprint,
}

/// A failure while deriving certificate log domains from one leaf DER value.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum CertificateLogRecordFromLeafDerError {
    /// The exact bytes did not contain one parseable X.509 certificate.
    #[snafu(display("failed to parse leaf certificate"))]
    ParseCertificate {
        source: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },

    /// Bytes remained after the single leaf certificate DER value.
    #[snafu(display("leaf certificate DER has {len} trailing bytes"))]
    TrailingData { len: usize },

    /// The extended key usage extension could not be interpreted uniquely.
    #[snafu(display("failed to parse leaf certificate extended key usage"))]
    ExtendedKeyUsage {
        source: x509_parser::error::X509Error,
    },

    /// The certificate expiry lies outside chrono's supported timestamp range.
    #[snafu(display("leaf certificate expiry is outside the supported timestamp range"))]
    ExpiryOutOfRange,
}

impl CertificateLogRecord {
    /// Derives issuer, usage, expiry, and SHA-256 from the exact leaf DER bytes.
    pub fn from_leaf_der(
        recorded_at: DateTime<FixedOffset>,
        action: CertificateAction,
        chain: CertificateChainKey,
        leaf_der: &[u8],
    ) -> Result<Self, CertificateLogRecordFromLeafDerError> {
        let (remaining, certificate) = X509Certificate::from_der(leaf_der)
            .context(certificate_log_record_from_leaf_der_error::ParseCertificateSnafu)?;
        if !remaining.is_empty() {
            return certificate_log_record_from_leaf_der_error::TrailingDataSnafu {
                len: remaining.len(),
            }
            .fail();
        }
        let issuer = first_valid_issuer(&certificate);
        let usage = certificate
            .extended_key_usage()
            .context(certificate_log_record_from_leaf_der_error::ExtendedKeyUsageSnafu)?
            .map_or(CertificateUsage::Unrestricted, |extension| {
                match (extension.value.client_auth, extension.value.server_auth) {
                    (true, true) => CertificateUsage::ClientAndServer,
                    (true, false) => CertificateUsage::ClientOnly,
                    (false, true) => CertificateUsage::ServerOnly,
                    (false, false) => CertificateUsage::Other,
                }
            });
        let expires_at =
            DateTime::<Utc>::from_timestamp(certificate.validity().not_after.timestamp(), 0)
                .map(|datetime| datetime.fixed_offset())
                .context(certificate_log_record_from_leaf_der_error::ExpiryOutOfRangeSnafu)?;
        let fingerprint_bytes: [u8; 32] = Sha256::digest(leaf_der).into();
        let fingerprint = Sha256Fingerprint::from(fingerprint_bytes);

        Ok(Self {
            recorded_at,
            action,
            issuer,
            usage,
            chain,
            expires_at,
            fingerprint,
        })
    }
}

fn first_valid_issuer(certificate: &X509Certificate<'_>) -> Option<CertificateIssuer> {
    certificate
        .issuer()
        .iter_organization()
        .filter_map(|attribute| attribute.as_str().ok())
        .chain(
            certificate
                .issuer()
                .iter_common_name()
                .filter_map(|attribute| attribute.as_str().ok()),
        )
        .next()
        .map(CertificateIssuer::from)
}
