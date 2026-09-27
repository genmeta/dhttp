//! Identity-bound HTTP/3 endpoints and a process-wide transport network.
mod bootstrap;
mod transport;
mod trust;

pub mod certificate;
pub mod client;
pub mod endpoint;
pub mod error;
pub mod home;
pub mod network;

pub use endpoint::{Endpoint, Request};
pub use error::{Error, Result};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
pub use network::DhttpNetwork;
pub use qconn::{Scope, Scopes};
pub use qtls::{CertificateDer, HandshakeSummary, LocalAuthority, RemoteAuthority};

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type EmptyBody = http_body_util::Empty<bytes::Bytes>;
pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;
pub type RequestFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<http::Response<Body>>> + Send + 'static>,
>;

#[cfg(feature = "access")]
pub use dhttp_access as access;
#[cfg(feature = "log")]
pub use dhttp_log as log;
