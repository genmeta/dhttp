//! HTTP access log records and their default formatter.

pub mod formatter;
pub mod record;

pub use formatter::DefaultAccessFormatter;
pub use record::{
    AccessCompletion, AccessLogRecord, AccessRequestTarget, BodyBytesEmitted, ClientAddress,
    InvalidAccessRequestTarget, OptionalReferer, OptionalUserAgent, RequestCompletedAt,
    RequestElapsed,
};
