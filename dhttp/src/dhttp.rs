//! HTTP/3 endpoints with optional client identity and a process-wide network.
mod bootstrap;
mod transport;
mod trust;
mod uri;

pub mod client;
pub mod endpoint;
pub mod error;
pub mod network;

pub use endpoint::{Empty, Endpoint, Request, RequestWriter};
pub use error::{Error, Result};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
pub use network::DhttpNetwork;
pub use qconn::{Scope, Scopes};
pub use qprotocol::AddressBook;
pub use qrecovery::send::CancelStream;
pub use qresolve as resolve;
pub use qtls::{CertificateDer, HandshakeSummary, LocalAuthority, RemoteAuthority};

pub use h3x::{Body, BoxError, WndBuf};
pub type EmptyBody = http_body_util::Empty<bytes::Bytes>;
pub type RequestFuture<T = http::Response<Body>> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'static>>;

#[cfg(feature = "access")]
pub use dhttp_access as access;
#[cfg(feature = "log")]
pub use dhttp_log as log;
