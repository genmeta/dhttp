use std::{
    net::IpAddr,
    str::FromStr,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, FixedOffset};
use http::{HeaderMap, Method, StatusCode, Uri, Version, header};
use snafu::Snafu;

use crate::{SystemTimeConversionError, datetime_from_system_time};

/// The wall-clock time at which a request completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCompletedAt(DateTime<FixedOffset>);

impl RequestCompletedAt {
    /// Constructs a deterministic timestamp from an already precise date-time.
    #[must_use]
    pub fn new(value: DateTime<FixedOffset>) -> Self {
        Self(value)
    }

    /// Returns the precise completion date-time.
    #[must_use]
    pub fn as_datetime(&self) -> &DateTime<FixedOffset> {
        &self.0
    }
}

impl TryFrom<SystemTime> for RequestCompletedAt {
    type Error = SystemTimeConversionError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        datetime_from_system_time(value).map(Self)
    }
}

/// The remote IP address available to the HTTP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAddress {
    Unknown,
    Ip(IpAddr),
}

impl From<IpAddr> for ClientAddress {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

/// The path or asterisk request target retained for access logging.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessRequestTarget(Option<String>);

impl AccessRequestTarget {
    /// Returns the retained path/asterisk form, or `None` for an omitted target.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl From<&Uri> for AccessRequestTarget {
    fn from(value: &Uri) -> Self {
        match value.path() {
            "" => Self(None),
            path => Self(Some(path.to_owned())),
        }
    }
}

impl From<Uri> for AccessRequestTarget {
    fn from(value: Uri) -> Self {
        Self::from(&value)
    }
}

/// A request target that is not a path/asterisk log domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Snafu)]
pub enum InvalidAccessRequestTarget {
    #[snafu(display("access request target is empty"))]
    Empty,
    #[snafu(display("access request target contains a record delimiter"))]
    RecordDelimiter,
    #[snafu(display("access request target contains a query"))]
    Query,
    #[snafu(display("access request target contains a fragment"))]
    Fragment,
    #[snafu(display("access request target contains an authority"))]
    Authority,
    #[snafu(display("access request target is not an absolute path or asterisk"))]
    NotAbsolutePath,
}

impl FromStr for AccessRequestTarget {
    type Err = InvalidAccessRequestTarget;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(InvalidAccessRequestTarget::Empty);
        }
        if value.contains(['\r', '\n']) {
            return Err(InvalidAccessRequestTarget::RecordDelimiter);
        }
        if value.contains('?') {
            return Err(InvalidAccessRequestTarget::Query);
        }
        if value.contains('#') {
            return Err(InvalidAccessRequestTarget::Fragment);
        }
        if value.starts_with("//") {
            return Err(InvalidAccessRequestTarget::Authority);
        }
        if value != "*" && !value.starts_with('/') {
            return Err(InvalidAccessRequestTarget::NotAbsolutePath);
        }
        Ok(Self(Some(value.to_owned())))
    }
}

/// The number of HTTP DATA bytes emitted to the body consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyBytesEmitted(u64);

impl BodyBytesEmitted {
    pub const ZERO: Self = Self(0);

    /// Returns the exact emitted byte count.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// Adds one emitted DATA frame length without saturating or wrapping.
    #[must_use]
    pub fn checked_add(self, additional: usize) -> Option<Self> {
        let additional = u64::try_from(additional).ok()?;
        self.0.checked_add(additional).map(Self)
    }
}

impl From<u64> for BodyBytesEmitted {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// The allowlisted Referer header value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OptionalReferer(Option<Vec<u8>>);

impl OptionalReferer {
    /// Returns the exact header bytes when present.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

impl From<&HeaderMap> for OptionalReferer {
    fn from(headers: &HeaderMap) -> Self {
        Self(
            headers
                .get(header::REFERER)
                .map(|value| value.as_bytes().to_vec()),
        )
    }
}

/// The allowlisted User-Agent header value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OptionalUserAgent(Option<Vec<u8>>);

impl OptionalUserAgent {
    /// Returns the exact header bytes when present.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

impl From<&HeaderMap> for OptionalUserAgent {
    fn from(headers: &HeaderMap) -> Self {
        Self(
            headers
                .get(header::USER_AGENT)
                .map(|value| value.as_bytes().to_vec()),
        )
    }
}

/// The monotonic elapsed duration from request entry through completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestElapsed(Duration);

impl RequestElapsed {
    /// Returns the exact monotonic duration.
    #[must_use]
    pub fn as_duration(self) -> Duration {
        self.0
    }
}

impl From<Duration> for RequestElapsed {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

/// How response-body observation completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessCompletion {
    Complete,
    BodyError,
    Aborted,
}

/// One HTTP access log record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessLogRecord {
    pub completed_at: RequestCompletedAt,
    pub client: ClientAddress,
    pub method: Method,
    pub target: AccessRequestTarget,
    pub version: Version,
    pub status: StatusCode,
    pub body_bytes: BodyBytesEmitted,
    pub referer: OptionalReferer,
    pub user_agent: OptionalUserAgent,
    pub elapsed: RequestElapsed,
    pub completion: AccessCompletion,
}
