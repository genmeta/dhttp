//! Named HTTP/3 endpoints, anonymous outbound requests and a process-wide network.
mod bootstrap;
mod transport;
mod trust;
mod uri;

pub mod client;
pub mod endpoint;
pub mod error;
pub mod network;

pub use endpoint::{Anonymous, Empty, Endpoint, Request, RequestWriter};
pub use error::{Error, Result};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
pub use network::DhttpNetwork;
pub use qconn::{Scope, Scopes};
pub use qprotocol::AddressBook;
pub use qrecovery::send::CancelStream;
pub use qresolve as resolve;
pub use qtls::{CertificateDer, HandshakeSummary, LocalAuthority, RemoteAuthority};

/// Supply an application Context before network initialization on Android.
/// This is needed when the embedding framework does not initialize `ndk-context`.
#[cfg(target_os = "android")]
pub use netwatcher::set_android_context;

pub use h3x::{Body, BoxError, WndBuf};
pub type ListenFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;
pub type EmptyBody = http_body_util::Empty<bytes::Bytes>;
pub type RequestFuture<T = http::Response<Body>> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'static>>;

#[cfg(feature = "access")]
pub use dhttp_access as access;
#[cfg(feature = "log")]
pub use dhttp_log as log;
