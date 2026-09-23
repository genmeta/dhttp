use std::sync::Arc;

use crate::{ArcWndBuf, Body, BoxError, Method, Request, Result, Uri};

/// A named DHTTP participant. Clones share the same logical name instance.
/// Network resolves credentials and connections when this participant is used.
#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

impl Endpoint {
    /// Resolve and validate a named participant without owning transport state.
    /// Credential lookup for a new connection or listener belongs to Network.
    pub async fn load(servername: impl AsRef<str>) -> Result<Self> {
        todo!("resolve and validate the DHTTP name")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Construct an editable request with no caller-written body. The caller
    /// parses the URI before this call; network I/O begins when await is polled.
    pub fn get(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound GET request")
    }

    pub fn head(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound HEAD request")
    }

    pub fn delete(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound DELETE request")
    }

    pub fn options(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound OPTIONS request")
    }

    pub fn post(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound POST request")
    }

    pub fn put(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound PUT request")
    }

    pub fn patch(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound PATCH request")
    }

    pub fn request(&self, method: Method, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an editable request for the specified method")
    }

    /// Register one application and drive it until stopped or an admission error.
    /// Same-endpoint duplicates fail with AlreadyListening; another active
    /// endpoint with the same normalized name fails with NameInUse.
    ///
    /// Service request extensions contain ArcConnection and HandshakeSummary
    /// from the actual accepted connection. Drive readiness and call on the
    /// same service instance. Body/trailers stay streaming.
    ///
    /// Cancelling listen cuts off admission and starts publication withdrawal.
    /// The caller owns all routing and application runtimes behind the Service.
    pub async fn listen<S, B>(&self, app: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        todo!("register and drive the application service")
    }
}
