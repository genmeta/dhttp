use std::{fmt::Display, time::Duration};

use chrono::{DateTime, TimeZone};
use snafu::Snafu;

use crate::record::RecordBuilder;

/// A failure while formatting one dynamic element.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum FormatElementError {
    /// A quoted wrapper was invoked while an outer quoted wrapper was active.
    #[snafu(display("nested quoted element presentation is not supported"))]
    NestedQuoted,

    /// Plain output contains an embedded physical record delimiter.
    #[snafu(display("element contains embedded record delimiter"))]
    RecordDelimiter { source: crate::RecordDelimiterError },

    /// Plain output contains an unsafe control or non-ASCII byte.
    #[snafu(display("element contains invalid byte {byte:#04x}"))]
    InvalidByte { byte: u8 },

    /// Appending the element would make the physical record too large.
    #[snafu(display("element exceeds maximum record length of {max_len} bytes"))]
    TooLong { max_len: usize },

    /// The HTTP version has no canonical compact representation.
    #[snafu(display("unsupported HTTP version {version:?}"))]
    UnsupportedHttpVersion { version: http::Version },
}

/// The open extension point for formatting a typed value under convention `C`.
pub trait FormatElement<C> {
    /// Writes this element through the convention's restricted element writer.
    fn format_element(
        &self,
        convention: &C,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresentationMode {
    Plain,
    Quoted,
}

/// Restricted output used by [`FormatElement`] implementations.
pub struct ElementWriter<'a> {
    builder: &'a mut RecordBuilder,
    mode: PresentationMode,
}

impl ElementWriter<'_> {
    pub(crate) fn new(builder: &mut RecordBuilder) -> ElementWriter<'_> {
        ElementWriter {
            builder,
            mode: PresentationMode::Plain,
        }
    }

    /// Appends dynamic bytes, validating or escaping them for the active mode.
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), FormatElementError> {
        match self.mode {
            PresentationMode::Plain => self.builder.append_plain(value),
            PresentationMode::Quoted => self.builder.append_quoted(value),
        }
    }

    fn quoted<C, E>(&mut self, convention: &C, value: &E) -> Result<(), FormatElementError>
    where
        E: FormatElement<C>,
    {
        if self.mode == PresentationMode::Quoted {
            return format_element_error::NestedQuotedSnafu.fail();
        }

        self.builder.append_quote_delimiter()?;
        value.format_element(
            convention,
            &mut ElementWriter {
                builder: self.builder,
                mode: PresentationMode::Quoted,
            },
        )?;
        self.builder.append_quote_delimiter()
    }
}

/// The default compact ASCII formatting convention.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompactConvention {
    _private: (),
}

/// Formats an element inside double quotes with canonical byte escaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quoted<E>(pub E);

impl<C, E> FormatElement<C> for Quoted<E>
where
    E: FormatElement<C>,
{
    fn format_element(
        &self,
        convention: &C,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        output.quoted(convention, &self.0)
    }
}

/// Formats `None` as the compact missing marker (`-`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Optional<E>(pub Option<E>);

impl<E> FormatElement<CompactConvention> for Optional<E>
where
    E: FormatElement<CompactConvention>,
{
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        match &self.0 {
            Some(value) => value.format_element(convention, output),
            None => output.bytes(b"-"),
        }
    }
}

/// Formats a timestamp in Common Log Format notation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClfTimestamp<T>(pub T);

impl<Tz> FormatElement<CompactConvention> for ClfTimestamp<DateTime<Tz>>
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        output.bytes(
            self.0
                .format("[%d/%b/%Y:%H:%M:%S %z]")
                .to_string()
                .as_bytes(),
        )
    }
}

/// Formats an integer in base ten.
///
/// Floating-point values are not decimal integer elements:
///
/// ```compile_fail
/// use dhttp_log::{CompactConvention, Decimal, FormatElement};
///
/// fn require_compact<E: FormatElement<CompactConvention>>(_element: &E) {}
/// require_compact(&Decimal(1.25_f64));
/// ```
///
/// String-like values must define their own typed element contract:
///
/// ```compile_fail
/// use dhttp_log::{CompactConvention, Decimal, FormatElement};
///
/// fn require_compact<E: FormatElement<CompactConvention>>(_element: &E) {}
/// require_compact(&Decimal("123"));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decimal<N>(pub N);

macro_rules! impl_decimal_integer {
    ($($integer:ty),+ $(,)?) => {
        $(
            impl FormatElement<CompactConvention> for Decimal<$integer> {
                fn format_element(
                    &self,
                    _convention: &CompactConvention,
                    output: &mut ElementWriter<'_>,
                ) -> Result<(), FormatElementError> {
                    output.bytes(self.0.to_string().as_bytes())
                }
            }
        )+
    };
}

impl_decimal_integer!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize,
);

/// Formats a duration as seconds with three rounded decimal places.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecondsMillis<T>(pub T);

impl FormatElement<CompactConvention> for SecondsMillis<Duration> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        let total_nanos = self.0.as_nanos();
        let rounded_millis = (total_nanos + 500_000) / 1_000_000;
        let seconds = rounded_millis / 1_000;
        let millis = rounded_millis % 1_000;
        output.bytes(format!("{seconds}.{millis:03}").as_bytes())
    }
}
