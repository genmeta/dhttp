use std::io::{self, Write};

use snafu::{ResultExt, Snafu};
use tracing_subscriber::fmt::MakeWriter;

use crate::{FilterRecord, FormatError, FormatRecord};

/// The observable outcome of one successful delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// The filter rejected the record before formatting or writer acquisition.
    Filtered,
    /// The external writer accepted the complete record through `write_all`.
    Written,
}

/// A failure while formatting or immediately writing one domain record.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DeliverRecordError {
    /// The formatter could not construct a complete physical record.
    #[snafu(display("failed to format domain log record"))]
    Format { source: FormatError },

    /// The acquired external writer rejected the immediate write.
    ///
    /// This failure is not atomic: `write_all` may have delivered a prefix before returning the
    /// source error. The adapter cannot roll that prefix back.
    #[snafu(display("failed to write domain log record"))]
    Write { source: io::Error },
}

/// A borrowed adapter that delivers complete records to an external `MakeWriter`.
#[derive(Debug)]
pub struct MakeWriterSink<'a, M: ?Sized> {
    make_writer: &'a M,
}

impl<'a, M: ?Sized> MakeWriterSink<'a, M> {
    /// Borrows a caller-owned writer factory without acquiring a writer.
    #[must_use]
    pub fn new(make_writer: &'a M) -> Self {
        Self { make_writer }
    }
}

impl<M> MakeWriterSink<'_, M>
where
    M: for<'writer> MakeWriter<'writer> + ?Sized,
{
    /// Filters, formats, acquires, and writes in that strict order.
    ///
    /// # Immediate write failures
    ///
    /// Delivery uses [`Write::write_all`]. A returned write error preserves its [`io::Error`]
    /// source, but the external writer may already have accepted a prefix of the record. Callers
    /// must not blindly retry the entire record after an error. This adapter provides no rollback,
    /// flush, synchronization, or durability guarantee.
    pub fn deliver<R, P, F>(
        &self,
        record: &R,
        filter: &P,
        formatter: &F,
    ) -> Result<DeliveryOutcome, DeliverRecordError>
    where
        P: FilterRecord<R>,
        F: FormatRecord<R>,
    {
        if !filter.enabled(record) {
            return Ok(DeliveryOutcome::Filtered);
        }

        let formatted = formatter
            .format_record(record)
            .context(deliver_record_error::FormatSnafu)?;
        let mut writer = self.make_writer.make_writer();
        writer
            .write_all(formatted.as_bytes())
            .context(deliver_record_error::WriteSnafu)?;
        Ok(DeliveryOutcome::Written)
    }
}
