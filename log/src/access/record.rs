use std::{net::IpAddr, str::FromStr};

use chrono::{DateTime, FixedOffset};
use http::{
    HeaderMap, Method, StatusCode, Uri, Version, header,
    uri::{InvalidUri, PathAndQuery},
};
use snafu::{ResultExt, Snafu};

/// The remote IP address available to the HTTP server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAddress {
    /// No client IP address was available at the HTTP boundary.
    Unknown,
    /// The request's client IP address, without a transport port.
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
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidAccessRequestTarget {
    /// The target has no bytes and therefore cannot be an origin path.
    #[snafu(display("access request target is empty"))]
    Empty,
    /// The target includes a query, which access records deliberately discard.
    #[snafu(display("access request target contains a query"))]
    Query,
    /// The target includes a URI fragment, which is not sent in an HTTP request target.
    #[snafu(display("access request target contains a fragment"))]
    Fragment,
    /// The target has network-path authority syntax rather than origin-path syntax.
    #[snafu(display("access request target contains an authority"))]
    Authority,
    /// The target is neither the asterisk form nor an absolute origin path.
    #[snafu(display("access request target is not an absolute path or asterisk"))]
    NotAbsolutePath,
    /// The path contains raw non-ASCII text instead of percent-encoded octets.
    #[snafu(display("access request target contains a non-ASCII path character"))]
    NonAscii,
    /// The path contains an ASCII control byte, including DEL.
    #[snafu(display("access request target contains an ASCII control character"))]
    ControlCharacter,
    /// The HTTP URI parser rejected the path bytes.
    #[snafu(display("access request target is not a valid HTTP path"))]
    InvalidUri { source: InvalidUri },
}

impl FromStr for AccessRequestTarget {
    type Err = InvalidAccessRequestTarget;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(InvalidAccessRequestTarget::Empty);
        }
        if value == "*" {
            return Ok(Self(Some(value.to_owned())));
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
        if !value.starts_with('/') {
            return Err(InvalidAccessRequestTarget::NotAbsolutePath);
        }

        let path = value
            .parse::<PathAndQuery>()
            .context(invalid_access_request_target::InvalidUriSnafu)?;
        debug_assert_eq!(path.path(), value);
        debug_assert!(path.query().is_none());

        if !value.is_ascii() {
            return Err(InvalidAccessRequestTarget::NonAscii);
        }
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(InvalidAccessRequestTarget::ControlCharacter);
        }
        Ok(Self(Some(value.to_owned())))
    }
}

/// The number of HTTP DATA bytes emitted to the body consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyBytesEmitted(u64);

impl BodyBytesEmitted {
    /// No DATA bytes were emitted.
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

/// One HTTP access log record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessLogRecord {
    /// Wall-clock time captured when response observation finalized.
    pub completed_at: DateTime<FixedOffset>,
    /// Client IP known at the HTTP boundary, without a transport port.
    pub client: ClientAddress,
    /// Typed HTTP request method.
    pub method: Method,
    /// Path-only or asterisk request target, with query and authority omitted.
    pub target: AccessRequestTarget,
    /// Typed HTTP protocol version.
    pub version: Version,
    /// Typed HTTP response status.
    pub status: StatusCode,
    /// DATA bytes actually emitted to the body consumer.
    pub body_bytes: BodyBytesEmitted,
    /// Allowlisted Referer header bytes, if present.
    pub referer: OptionalReferer,
    /// Allowlisted User-Agent header bytes, if present.
    pub user_agent: OptionalUserAgent,
}
