//! Typed formatting and delivery primitives for DHTTP domain logs.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use snafu::Snafu;

pub mod access;
pub mod cert;
mod compact;
mod filter;
mod format;
mod make_writer;
mod record;

pub use compact::{
    ClfTimestamp, CompactConvention, Decimal, ElementWriter, FormatElement, FormatElementError,
    Optional, Quoted, SecondsMillis,
};
pub use filter::{AllowAll, FilterRecord};
pub use format::FormatRecord;
pub use make_writer::{DeliverRecordError, DeliveryOutcome, MakeWriterSink};
pub use record::{
    FormatError, FormattedRecord, MAX_RECORD_LEN, RecordBuilder, RecordDelimiterError,
};

/// A checked wall-clock conversion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Snafu)]
pub enum SystemTimeConversionError {
    /// The value lies before chrono's representable timestamp range.
    #[snafu(display("system time is before the supported timestamp range"))]
    BeforeSupportedRange,

    /// The value lies after chrono's representable timestamp range.
    #[snafu(display("system time is after the supported timestamp range"))]
    AfterSupportedRange,
}

pub(crate) fn datetime_from_system_time(
    value: SystemTime,
) -> Result<DateTime<FixedOffset>, SystemTimeConversionError> {
    let (seconds, nanoseconds) = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let seconds = i64::try_from(duration.as_secs())
                .map_err(|_| SystemTimeConversionError::AfterSupportedRange)?;
            (seconds, duration.subsec_nanos())
        }
        Err(error) => {
            let duration = error.duration();
            let magnitude = i64::try_from(duration.as_secs())
                .map_err(|_| SystemTimeConversionError::BeforeSupportedRange)?;
            if duration.subsec_nanos() == 0 {
                let seconds = magnitude
                    .checked_neg()
                    .ok_or(SystemTimeConversionError::BeforeSupportedRange)?;
                (seconds, 0)
            } else {
                let seconds = magnitude
                    .checked_add(1)
                    .and_then(i64::checked_neg)
                    .ok_or(SystemTimeConversionError::BeforeSupportedRange)?;
                (seconds, 1_000_000_000 - duration.subsec_nanos())
            }
        }
    };

    DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
        .map(|datetime| datetime.fixed_offset())
        .ok_or(if seconds.is_negative() {
            SystemTimeConversionError::BeforeSupportedRange
        } else {
            SystemTimeConversionError::AfterSupportedRange
        })
}
