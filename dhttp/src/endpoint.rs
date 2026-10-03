//! Named HTTP/3 endpoints and request handling.
use crate::{Body, BoxError, Error, Result, network::DhttpNetwork};
use bytes::Bytes;
use h3x::{ReadRequest, WndBuf, WriteResponse};
use http_body_util::BodyExt;
use qconn::Scopes;
use qrecovery::send::CancelStream;
use std::sync::Arc;
use tower::ServiceExt;
use tower_service::Service;

mod request;
pub use request::{Empty, Request, RequestWriter};

/// Anonymous outbound HTTP/3 requests. The server's identity is still verified.
/// Request methods match [`Endpoint`], without local credentials or listening.
///
/// ```no_run
/// # async fn example(uri: dhttp::Uri) -> dhttp::Result<()> {
/// let response = dhttp::Anonymous.get(uri).await?;
/// # Ok(())
/// # }
/// ```
///
/// ```compile_fail,E0599
/// dhttp::Anonymous.listen(Default::default(), ());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Anonymous;

impl Anonymous {
    pub fn get(&self, uri: http::Uri) -> Request<Empty> {
        empty_request(None, http::Method::GET, uri)
    }
    pub fn head(&self, uri: http::Uri) -> Request<Empty> {
        empty_request(None, http::Method::HEAD, uri)
    }
    pub fn post(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::POST, uri)
    }
    pub fn put(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::PUT, uri)
    }
    pub fn patch(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::PATCH, uri)
    }
    pub fn delete(&self, uri: http::Uri) -> Request<Empty> {
        empty_request(None, http::Method::DELETE, uri)
    }
    pub fn options(&self, uri: http::Uri) -> Request<Empty> {
        empty_request(None, http::Method::OPTIONS, uri)
    }
    /// Open a streaming request. Await it for a RequestWriter and a response future.
    /// Call AsyncWriteExt::shutdown() on the returned writer to end the request body.
    pub fn request(&self, method: http::Method, uri: http::Uri) -> Request<WndBuf> {
        empty_request(None, method, uri).body(WndBuf::new(request::REQUEST_WINDOW_BYTES))
    }
    /// Use a standard request with `Empty` or `WndBuf` without local credentials.
    pub fn from_request<B>(&self, request: http::Request<B>) -> Request<B> {
        Request::new(request)
    }
}

fn empty_request(
    endpoint: Option<Endpoint>,
    method: http::Method,
    uri: http::Uri,
) -> Request<Empty> {
    let mut message = http::Request::new(Empty::new());
    *message.method_mut() = method;
    *message.uri_mut() = uri;
    Request { endpoint, message }
}

/// A named HTTP/3 endpoint with local QUIC credentials for requests and listening.
///
/// ```compile_fail
/// let endpoint = dhttp::Endpoint::new(None);
/// ```
#[derive(Clone)]
pub struct Endpoint {
    pub(crate) quic: Arc<qconn::QuicEndpoint>,
}

impl Endpoint {
    /// Create a named endpoint from prepared local QUIC credentials.
    pub fn new(identity: Arc<qbase::endpoint::Endpoint>) -> Self {
        let mut quic = qconn::QuicEndpoint::new(identity);
        quic.alpn = vec![h3x::ALPN.to_vec()];
        quic.client_parameters = qbase::param::handy::client_parameters();
        quic.server_parameters = qbase::param::handy::server_parameters();
        Self {
            quic: Arc::new(quic),
        }
    }

    /// Load the named identity's certificate chain, private key and OCSP staple.
    /// Clones share the loaded QUIC endpoint; no network access is performed.
    pub async fn load(name: impl AsRef<str>) -> Result<Self> {
        let name = dhttp_home::normalize_name(name.as_ref()).ok_or_else(|| Error::InvalidName {
            name: name.as_ref().to_owned(),
        })?;
        let home = dhttp_home::DhttpHome::load(dhttp_home::HomeScope::User).map_err(|error| {
            Error::HomeUnavailable {
                message: error.to_string(),
            }
        })?;
        let profile = home
            .identity_profile(&name)
            .map_err(|_| Error::InvalidName { name })?;
        let certificates = profile.load_certs().await.map_err(|source| Error::Home {
            path: profile.cert_path(),
            source: Arc::new(source),
        })?;
        let key = profile.load_key().await.map_err(|source| Error::Home {
            path: profile.key_path(),
            source: Arc::new(source),
        })?;
        let ocsp = profile.load_ocsp().await.map_err(|source| Error::Home {
            path: profile.ocsp_path(),
            source: Arc::new(source),
        })?;
        let identity = qbase::endpoint::Endpoint::new(
            &qtls::default_provider(),
            profile.name(),
            certificates,
            key,
            ocsp,
        )
        .map_err(|source| Error::Credentials {
            source: Arc::new(source),
        })?;
        Ok(Self::new(identity))
    }
    /// The local identity's name.
    pub fn name(&self) -> &str {
        self.quic.identity.name()
    }
    pub fn get(&self, uri: http::Uri) -> Request<Empty> {
        self.empty_request(http::Method::GET, uri)
    }
    pub fn head(&self, uri: http::Uri) -> Request<Empty> {
        self.empty_request(http::Method::HEAD, uri)
    }
    pub fn post(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::POST, uri)
    }
    pub fn put(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::PUT, uri)
    }
    pub fn patch(&self, uri: http::Uri) -> Request<WndBuf> {
        self.request(http::Method::PATCH, uri)
    }
    pub fn delete(&self, uri: http::Uri) -> Request<Empty> {
        self.empty_request(http::Method::DELETE, uri)
    }
    pub fn options(&self, uri: http::Uri) -> Request<Empty> {
        self.empty_request(http::Method::OPTIONS, uri)
    }
    /// Open a streaming request. Await it for a RequestWriter and a response future.
    /// Call AsyncWriteExt::shutdown() on the returned writer to end the request body.
    pub fn request(&self, method: http::Method, uri: http::Uri) -> Request<WndBuf> {
        self.empty_request(method, uri)
            .body(WndBuf::new(request::REQUEST_WINDOW_BYTES))
    }

    fn empty_request(&self, method: http::Method, uri: http::Uri) -> Request<Empty> {
        empty_request(Some(self.clone()), method, uri)
    }
    /// Bind a standard request with `Empty` or `WndBuf` to this endpoint.
    pub fn from_request<B>(&self, request: http::Request<B>) -> Request<B> {
        Request::bound(self.clone(), request)
    }

    pub async fn listen<S, B>(&self, scopes: Scopes, service: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let network = DhttpNetwork::global()?;
        let service = service
            .map_err(Into::into)
            .map_response(|response| response.map(|body| body.map_err(Into::into).boxed_unsync()))
            .boxed_clone();
        network.listen(self, scopes, service).await
    }
}

pub(crate) async fn handle_request<W, R>(
    app: crate::network::BoxService,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
    handshake: Arc<qtls::HandshakeSummary>,
) -> Result<()>
where
    W: WriteResponse + CancelStream,
    R: ReadRequest,
{
    // Application failures have no response to encode, so end our write direction.
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
    });
    let mut request = reader.read_request(qpack.clone()).await?;
    let method = request.method().clone();
    let uri = handshake.local.as_ref().and_then(|local| {
        let uri =
            crate::uri::expand_uri_with_base(Some(local.name()), request.uri().clone()).ok()?;
        let authority = uri.authority()?;
        (!authority.as_str().contains('@')
            && authority
                .host()
                .strip_suffix('.')
                .unwrap_or(authority.host())
                .eq_ignore_ascii_case(local.name()))
        .then_some(uri)
    });
    let Some(uri) = uri else {
        drop(request);
        let mut response = http::Response::new(Body::default());
        *response.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
        return scopeguard::ScopeGuard::into_inner(writer)
            .write_response(response, method, qpack)
            .await
            .map_err(Error::from);
    };
    *request.uri_mut() = uri;
    request.extensions_mut().insert((*handshake).clone());
    let mut app = app;
    futures::future::poll_fn(|cx| app.poll_ready(cx)).await?;
    let response = app.call(request).await?;
    match scopeguard::ScopeGuard::into_inner(writer)
        .write_response(response, method, qpack)
        .await
    {
        // A peer declining the remaining response does not fail the service call.
        Err(h3x::Error::Stream(detail)) if detail.code == h3x::ErrorCode::NoError => Ok(()),
        result => result.map_err(Error::from),
    }
}

#[cfg(test)]
#[path = "../tests/unit/endpoint.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/support/endpoint.rs"]
pub(crate) mod test_support;
