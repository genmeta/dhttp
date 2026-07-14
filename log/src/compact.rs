use std::fmt::Display;

use chrono::{DateTime, FixedOffset, TimeZone};

use crate::{FormatError, record::RecordBuilder};

/// The open extension point for formatting a typed value under convention `C`.
pub(crate) trait FormatElement<C> {
    /// Writes this element through the convention's restricted element writer.
    fn format_element(
        &self,
        convention: &C,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresentationMode {
    Plain,
    Quoted,
}

/// Restricted output used by [`FormatElement`] implementations.
pub(crate) struct ElementWriter<'a> {
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
    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), FormatError> {
        match self.mode {
            PresentationMode::Plain => self.builder.append_plain(value),
            PresentationMode::Quoted => self.builder.append_quoted(value),
        }
    }

    fn quoted<C, E>(&mut self, convention: &C, value: &E) -> Result<(), FormatError>
    where
        E: FormatElement<C>,
    {
        if self.mode == PresentationMode::Quoted {
            return Err(FormatError::NestedQuoted);
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
pub(crate) struct CompactConvention {
    _private: (),
}

/// Formats an element inside double quotes with canonical byte escaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Quoted<E>(pub E);

impl<C, E> FormatElement<C> for Quoted<E>
where
    E: FormatElement<C>,
{
    fn format_element(
        &self,
        convention: &C,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.quoted(convention, &self.0)
    }
}

/// Formats `None` as the compact missing marker (`-`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Optional<E>(pub Option<E>);

impl<E> FormatElement<CompactConvention> for Optional<E>
where
    E: FormatElement<CompactConvention>,
{
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        match &self.0 {
            Some(value) => value.format_element(convention, output),
            None => output.bytes(b"-"),
        }
    }
}

/// Formats a timestamp in Common Log Format notation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClfTimestamp<T>(pub T);

impl FormatElement<CompactConvention> for DateTime<FixedOffset> {
    fn format_element(
        &self,
        convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        ClfTimestamp(*self).format_element(convention, output)
    }
}

impl<Tz> FormatElement<CompactConvention> for ClfTimestamp<DateTime<Tz>>
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(
            self.0
                .format("[%d/%b/%Y:%H:%M:%S %z]")
                .to_string()
                .as_bytes(),
        )
    }
}

/// Formats an integer in base ten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Decimal<N>(pub N);

macro_rules! impl_decimal_integer {
    ($($integer:ty),+ $(,)?) => {
        $(
            impl FormatElement<CompactConvention> for Decimal<$integer> {
                fn format_element(
                    &self,
                    _convention: &CompactConvention,
                    output: &mut ElementWriter<'_>,
                ) -> Result<(), FormatError> {
                    output.bytes(self.0.to_string().as_bytes())
                }
            }
        )+
    };
}

impl_decimal_integer!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize,
);

#[cfg(test)]
mod tests;
