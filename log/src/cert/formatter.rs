use dhttp_identity::certificate::CertificateChainKey;

use crate::{
    FormatError, FormattedRecord,
    compact::{CompactConvention, ElementWriter, FormatElement, Optional, Quoted},
    record::RecordBuilder,
};

use super::record::{
    CertificateAction, CertificateIssuer, CertificateLogRecord, CertificateUsage, Sha256Fingerprint,
};

/// The compact V1 certificate lifecycle formatter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DefaultCertificateFormatter;

impl DefaultCertificateFormatter {
    /// Formats one certificate record using the built-in compact V1 representation.
    pub fn format(record: &CertificateLogRecord) -> Result<FormattedRecord, FormatError> {
        let convention = CompactConvention::default();
        let mut builder = RecordBuilder::new();
        builder.element(&convention, &record.recorded_at)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.action)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.issuer)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.usage)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.chain)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.expires_at)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.fingerprint)?;
        builder.finish()
    }
}

impl FormatElement<CompactConvention> for CertificateAction {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(match self {
            Self::Apply => b"APPLY",
            Self::Renew => b"RENEW",
            Self::Replace => b"REPLACE",
        })
    }
}

impl FormatElement<CompactConvention> for CertificateIssuer {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.as_str().as_bytes())
    }
}

impl FormatElement<CompactConvention> for Option<CertificateIssuer> {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        Optional(
            self.as_ref()
                .map(|issuer| Quoted(CertificateIssuerText(issuer))),
        )
        .format_element(convention, output)
    }
}

impl FormatElement<CompactConvention> for CertificateUsage {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        let usage = CertificateUsageText(match self {
            Self::ClientOnly => b"client only",
            Self::ServerOnly => b"server only",
            Self::ClientAndServer => b"client and server",
            Self::Unrestricted => b"unrestricted",
            Self::Other => b"other",
        });
        Quoted(usage).format_element(convention, output)
    }
}

struct CertificateUsageText(&'static [u8]);

struct CertificateIssuerText<'a>(&'a CertificateIssuer);

impl FormatElement<CompactConvention> for CertificateIssuerText<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0.as_str().as_bytes())
    }
}

impl FormatElement<CompactConvention> for CertificateUsageText {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0)
    }
}

impl FormatElement<CompactConvention> for CertificateChainKey {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.to_string().as_bytes())
    }
}

impl FormatElement<CompactConvention> for Sha256Fingerprint {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        let mut encoded = [0_u8; 71];
        encoded[..7].copy_from_slice(b"sha256:");
        for (index, byte) in self.as_bytes().iter().copied().enumerate() {
            encoded[7 + index * 2] = hex_digit(byte >> 4);
            encoded[8 + index * 2] = hex_digit(byte & 0x0f);
        }
        Quoted(FingerprintText(&encoded)).format_element(convention, output)
    }
}

struct FingerprintText<'a>(&'a [u8]);

impl FormatElement<CompactConvention> for FingerprintText<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0)
    }
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!("a nibble is always within the hexadecimal digit range"),
    }
}
