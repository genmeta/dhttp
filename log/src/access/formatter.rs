use crate::{
    FormatError, FormattedRecord,
    compact::{
        ClfTimestamp, CompactConvention, Decimal, ElementWriter, FormatElement, Optional, Quoted,
    },
    record::RecordBuilder,
};

use super::record::{
    AccessLogRecord, AccessRequestTarget, BodyBytesEmitted, ClientAddress, OptionalReferer,
    OptionalUserAgent, RequestCompletedAt,
};

/// The compact V1 combined access-log formatter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DefaultAccessFormatter;

impl DefaultAccessFormatter {
    /// Formats one access record using the built-in compact V1 representation.
    pub fn format(record: &AccessLogRecord) -> Result<FormattedRecord, FormatError> {
        let convention = CompactConvention::default();
        let mut builder = RecordBuilder::new();
        builder.element(&convention, &record.client)?;
        builder.literal(b" ")?;
        builder.element(&convention, &MissingField)?;
        builder.literal(b" ")?;
        builder.element(&convention, &MissingField)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.completed_at)?;
        builder.literal(b" ")?;
        builder.element(&convention, &Quoted(AccessRequestLine(record)))?;
        builder.literal(b" ")?;
        builder.element(&convention, &Decimal(record.status.as_u16()))?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.body_bytes)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.referer)?;
        builder.literal(b" ")?;
        builder.element(&convention, &record.user_agent)?;
        builder.finish()
    }
}

struct MissingField;

impl FormatElement<CompactConvention> for MissingField {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(b"-")
    }
}

impl FormatElement<CompactConvention> for RequestCompletedAt {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        ClfTimestamp(*self.as_datetime()).format_element(convention, output)
    }
}

impl FormatElement<CompactConvention> for ClientAddress {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        match self {
            Self::Unknown => output.bytes(b"-"),
            Self::Ip(address) => output.bytes(address.to_string().as_bytes()),
        }
    }
}

impl FormatElement<CompactConvention> for AccessRequestTarget {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        Optional(self.path().map(Text)).format_element(convention, output)
    }
}

struct AccessRequestLine<'a>(&'a AccessLogRecord);

impl FormatElement<CompactConvention> for AccessRequestLine<'_> {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0.method.as_str().as_bytes())?;
        output.bytes(b" ")?;
        self.0.target.format_element(convention, output)?;
        output.bytes(b" ")?;
        output.bytes(http_version(self.0.version)?)
    }
}

fn http_version(version: http::Version) -> Result<&'static [u8], FormatError> {
    match version {
        http::Version::HTTP_09 => Ok(b"HTTP/0.9"),
        http::Version::HTTP_10 => Ok(b"HTTP/1.0"),
        http::Version::HTTP_11 => Ok(b"HTTP/1.1"),
        http::Version::HTTP_2 => Ok(b"HTTP/2"),
        http::Version::HTTP_3 => Ok(b"HTTP/3"),
        _ => Err(FormatError::UnsupportedHttpVersion { version }),
    }
}

impl FormatElement<CompactConvention> for BodyBytesEmitted {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        Decimal(self.get()).format_element(convention, output)
    }
}

impl FormatElement<CompactConvention> for OptionalReferer {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        Quoted(Optional(self.value().map(Bytes))).format_element(convention, output)
    }
}

impl FormatElement<CompactConvention> for OptionalUserAgent {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        Quoted(Optional(self.value().map(Bytes))).format_element(convention, output)
    }
}

struct Text<'a>(&'a str);

impl FormatElement<CompactConvention> for Text<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0.as_bytes())
    }
}

struct Bytes<'a>(&'a [u8]);

impl FormatElement<CompactConvention> for Bytes<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0)
    }
}
