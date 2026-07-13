use crate::{FormatError, FormattedRecord};

/// Formats a typed domain record into one complete physical record.
pub trait FormatRecord<R>: Send + Sync {
    /// Formats `record` without performing delivery I/O.
    fn format_record(&self, record: &R) -> Result<FormattedRecord, FormatError>;
}
