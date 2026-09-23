//! DHTTP interfaces agreed in `docs/api/top-level-review.md`.
//!
//! Declaration-only stage: endpoint members and method signatures are defined,
//! but method bodies intentionally use `todo!()` and cannot be called yet.
// Temporary allowances for declaration-only members and method parameters.
#![allow(dead_code, unused_variables)]

mod bootstrap;
mod transport;
mod trust;

pub mod certificate;
pub mod client;
pub mod endpoint;
pub mod error;
pub mod home;
pub mod name;
pub mod network;

pub use client::{Request, Response};
pub use endpoint::Endpoint;
pub use error::{Error, Result, ShutdownReport};
pub use h3x::{ArcWndBuf, R, Trailers, W};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

pub use network::{DhttpNetwork, ListenConfig, NetworkConfig};
pub use qconn::{ArcConnection, Scope, Scopes};
pub use qtls::{HandshakeSummary, LocalAuthority, RemoteAuthority};

/// Error type accepted by the standard HTTP service boundary.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Streaming request body passed to application services.
pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;

#[cfg(feature = "access")]
pub use dhttp_access as access;
#[cfg(feature = "log")]
pub use dhttp_log as log;
