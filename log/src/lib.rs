//! Typed formatting and delivery primitives for DHTTP domain logs.

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
pub use record::{FormatError, FormattedRecord, MAX_RECORD_LEN, RecordBuilder};
