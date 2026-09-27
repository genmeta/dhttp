//! Typed formatting and delivery primitives for DHTTP domain logs.

pub mod access;
pub mod cert;
mod compact;
mod record;

pub use record::{FormatError, FormattedRecord, MAX_RECORD_LEN};
