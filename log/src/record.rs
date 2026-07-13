use snafu::{ResultExt, Snafu};

use crate::{FormatElement, FormatElementError, compact::ElementWriter};

/// Maximum physical record size, including its final line feed.
pub const MAX_RECORD_LEN: usize = 64 * 1024;

/// A complete physical log record ready for delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormattedRecord(Box<[u8]>);

impl FormattedRecord {
    /// Returns the complete record bytes, including the final line feed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for FormattedRecord {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The physical record delimiter found inside record content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Snafu)]
pub enum RecordDelimiterError {
    /// A carriage return (`CR`) appeared inside record content.
    #[snafu(display("embedded carriage return record delimiter"))]
    CarriageReturn,

    /// A line feed (`LF`) appeared inside record content.
    #[snafu(display("embedded line feed record delimiter"))]
    LineFeed,
}

/// A failure while assembling a complete physical record.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FormatError {
    /// A dynamic element could not be formatted safely.
    #[snafu(display("failed to format record element"))]
    Element { source: FormatElementError },

    /// A static literal contains an embedded physical record delimiter.
    #[snafu(display("record literal contains embedded record delimiter"))]
    RecordDelimiter { source: RecordDelimiterError },

    /// A static literal contains a byte that cannot appear inside a record.
    #[snafu(display("record literal contains invalid byte {byte:#04x}"))]
    InvalidLiteral { byte: u8 },

    /// The physical record would exceed [`MAX_RECORD_LEN`].
    #[snafu(display("record exceeds maximum length of {max_len} bytes"))]
    TooLong { max_len: usize },
}

/// Builds one bounded physical record from static literals and typed elements.
#[derive(Debug, Default)]
pub struct RecordBuilder {
    bytes: Vec<u8>,
}

impl RecordBuilder {
    /// Creates an empty record builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a source-code literal separator or template fragment.
    pub fn literal(&mut self, value: &'static [u8]) -> Result<(), FormatError> {
        for &byte in value {
            reject_record_delimiter(byte).context(format_error::RecordDelimiterSnafu)?;
            if !is_record_content_byte(byte) {
                return format_error::InvalidLiteralSnafu { byte }.fail();
            }
        }
        self.ensure_content_fits(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Appends a typed dynamic element using the selected convention.
    pub fn element<C, E>(&mut self, convention: &C, value: &E) -> Result<(), FormatError>
    where
        E: FormatElement<C>,
    {
        let checkpoint = self.bytes.len();
        let result = value.format_element(convention, &mut ElementWriter::new(self));
        if result.is_err() {
            self.bytes.truncate(checkpoint);
        }
        result.context(format_error::ElementSnafu)
    }

    /// Finalizes the record by appending exactly one line feed.
    pub fn finish(mut self) -> Result<FormattedRecord, FormatError> {
        self.ensure_content_fits(0)?;
        self.bytes.push(b'\n');
        Ok(FormattedRecord(self.bytes.into_boxed_slice()))
    }

    pub(crate) fn append_plain(&mut self, value: &[u8]) -> Result<(), FormatElementError> {
        for &byte in value {
            reject_record_delimiter(byte)
                .context(crate::compact::format_element_error::RecordDelimiterSnafu)?;
            if !is_record_content_byte(byte) {
                return Err(FormatElementError::InvalidByte { byte });
            }
        }
        self.ensure_element_fits(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_quoted(&mut self, value: &[u8]) -> Result<(), FormatElementError> {
        let additional = value.iter().try_fold(0_usize, |length, byte| {
            let encoded_len = match byte {
                b'"' | b'\\' => 2,
                byte if byte.is_ascii_control() || !byte.is_ascii() => 4,
                _ => 1,
            };
            length
                .checked_add(encoded_len)
                .ok_or(crate::compact::FormatElementError::TooLong {
                    max_len: MAX_RECORD_LEN,
                })
        })?;
        self.ensure_element_fits(additional)?;

        for &byte in value {
            match byte {
                b'"' => self.bytes.extend_from_slice(b"\\\""),
                b'\\' => self.bytes.extend_from_slice(b"\\\\"),
                byte if byte.is_ascii_control() || !byte.is_ascii() => {
                    self.bytes.extend_from_slice(b"\\x");
                    self.bytes.push(hex_digit(byte >> 4));
                    self.bytes.push(hex_digit(byte & 0x0f));
                }
                byte => self.bytes.push(byte),
            }
        }
        Ok(())
    }

    pub(crate) fn append_trusted(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), FormatElementError> {
        self.ensure_element_fits(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn ensure_content_fits(&self, additional: usize) -> Result<(), FormatError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length >= MAX_RECORD_LEN)
        {
            return format_error::TooLongSnafu {
                max_len: MAX_RECORD_LEN,
            }
            .fail();
        }
        Ok(())
    }

    fn ensure_element_fits(&self, additional: usize) -> Result<(), FormatElementError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length >= MAX_RECORD_LEN)
        {
            return Err(FormatElementError::TooLong {
                max_len: MAX_RECORD_LEN,
            });
        }
        Ok(())
    }
}

fn is_record_content_byte(byte: u8) -> bool {
    byte.is_ascii() && !byte.is_ascii_control()
}

fn reject_record_delimiter(byte: u8) -> Result<(), RecordDelimiterError> {
    match byte {
        b'\r' => Err(RecordDelimiterError::CarriageReturn),
        b'\n' => Err(RecordDelimiterError::LineFeed),
        _ => Ok(()),
    }
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!("a nibble always fits in one hexadecimal digit"),
    }
}
