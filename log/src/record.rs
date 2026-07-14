use snafu::Snafu;

use crate::compact::{ElementWriter, FormatElement};

/// Maximum physical record size, including its final line feed.
pub const MAX_RECORD_LEN: usize = 64 * 1024;

/// A complete physical log record ready for delivery.
///
/// Every value of this type satisfies these physical invariants:
///
/// - its length is at most [`MAX_RECORD_LEN`] (64 KiB), including the final line feed;
/// - every byte is ASCII;
/// - no carriage return or line feed appears before the record delimiter;
/// - exactly one line feed terminates the record.
///
/// Construction is private to [`RecordBuilder::finish`].
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

/// A failure while assembling a complete physical record.
#[derive(Debug, Eq, PartialEq, Snafu)]
pub enum FormatError {
    /// A quoted formatter was nested inside another quoted formatter.
    #[snafu(display("nested quoted element presentation is not supported"))]
    NestedQuoted,

    /// A carriage return appeared before the record delimiter.
    #[snafu(display("embedded carriage return record delimiter"))]
    CarriageReturn,

    /// A line feed appeared before the record delimiter.
    #[snafu(display("embedded line feed record delimiter"))]
    LineFeed,

    /// Plain output contains an unsafe control or non-ASCII byte.
    #[snafu(display("record contains invalid byte {byte:#04x}"))]
    InvalidByte { byte: u8 },

    /// The HTTP version has no canonical compact representation.
    #[snafu(display("unsupported HTTP version {version:?}"))]
    UnsupportedHttpVersion { version: http::Version },

    /// The physical record would exceed [`MAX_RECORD_LEN`].
    #[snafu(display("record exceeds maximum length of {max_len} bytes"))]
    TooLong { max_len: usize },
}

/// Builds one bounded physical record from static literals and typed elements.
#[derive(Debug, Default)]
pub(crate) struct RecordBuilder {
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
            reject_record_delimiter(byte)?;
            if !is_record_content_byte(byte) {
                return Err(FormatError::InvalidByte { byte });
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
        result
    }

    /// Finalizes a validated [`FormattedRecord`] by appending exactly one line feed.
    ///
    /// The returned physical record is ASCII, has no embedded carriage returns or line feeds,
    /// and is at most [`MAX_RECORD_LEN`] bytes including its single final line feed.
    pub fn finish(mut self) -> Result<FormattedRecord, FormatError> {
        self.ensure_content_fits(0)?;
        self.bytes.push(b'\n');
        Ok(FormattedRecord(self.bytes.into_boxed_slice()))
    }

    pub(crate) fn append_plain(&mut self, value: &[u8]) -> Result<(), FormatError> {
        for &byte in value {
            reject_record_delimiter(byte)?;
            if !is_record_content_byte(byte) {
                return Err(FormatError::InvalidByte { byte });
            }
        }
        self.ensure_element_fits(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_quoted(&mut self, value: &[u8]) -> Result<(), FormatError> {
        let additional = value.iter().try_fold(0_usize, |length, byte| {
            let encoded_len = match byte {
                b'"' | b'\\' => 2,
                byte if byte.is_ascii_control() || !byte.is_ascii() => 4,
                _ => 1,
            };
            length.checked_add(encoded_len).ok_or(FormatError::TooLong {
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

    pub(crate) fn append_quote_delimiter(&mut self) -> Result<(), FormatError> {
        self.ensure_element_fits(1)?;
        self.bytes.push(b'"');
        Ok(())
    }

    fn ensure_content_fits(&self, additional: usize) -> Result<(), FormatError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length >= MAX_RECORD_LEN)
        {
            return Err(FormatError::TooLong {
                max_len: MAX_RECORD_LEN,
            });
        }
        Ok(())
    }

    fn ensure_element_fits(&self, additional: usize) -> Result<(), FormatError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|length| length >= MAX_RECORD_LEN)
        {
            return Err(FormatError::TooLong {
                max_len: MAX_RECORD_LEN,
            });
        }
        Ok(())
    }
}

fn is_record_content_byte(byte: u8) -> bool {
    byte.is_ascii() && !byte.is_ascii_control()
}

fn reject_record_delimiter(byte: u8) -> Result<(), FormatError> {
    match byte {
        b'\r' => Err(FormatError::CarriageReturn),
        b'\n' => Err(FormatError::LineFeed),
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
