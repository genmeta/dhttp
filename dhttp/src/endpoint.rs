//! Identity-bound request and response handling.
use crate::{Body, BoxError, EmptyBody, Error, Result, network::DhttpNetwork};
use bytes::Bytes;
use h3x::{ReadRequest, WriteResponse};
use http_body_util::{BodyExt, StreamBody};
use qconn::Scopes;
use qrecovery::{recv::StopSending, send::CancelStream};
use std::sync::Arc;
use tower::ServiceExt;
use tower_service::Service;

const BODY_WINDOW_BYTES: usize = 64 * 1024;
// Match h3x's receive chunk so each Body frame can transfer its Bytes directly.
const BODY_READ_CHUNK_BYTES: usize = 8 * 1024;
mod body;
mod request;
mod response;
use body::forward_inbound_body;
use response::send_response;

// TODO: 这个替换成 dquic endpoint
#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

#[must_use = "configure and await the request to send it"]
pub struct Request<B> {
    endpoint: Endpoint,
    message: http::Request<B>,
}

impl Endpoint {
    pub async fn load(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: Arc::from(dhttp_home::normalize_name(name.as_ref()).ok_or_else(|| {
                Error::InvalidName {
                    name: name.as_ref().to_owned(),
                }
            })?),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn get(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::GET, uri)
    }
    pub fn head(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::HEAD, uri)
    }
    pub fn post(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::POST, uri)
    }
    pub fn put(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PUT, uri)
    }
    pub fn patch(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PATCH, uri)
    }
    pub fn delete(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::DELETE, uri)
    }
    pub fn options(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::OPTIONS, uri)
    }
    pub fn request(&self, method: http::Method, uri: http::Uri) -> Request<EmptyBody> {
        let mut message = http::Request::new(EmptyBody::new());
        *message.method_mut() = method;
        *message.uri_mut() = uri;
        self.from_request(message)
    }
    pub fn from_request<B>(&self, request: http::Request<B>) -> Request<B> {
        Request {
            endpoint: self.clone(),
            message: request,
        }
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
        network.listen(self.name.clone(), scopes, service).await
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
    let incoming = reader.read_request(qpack.clone()).await?;
    let (mut parts, mut inbound) = incoming.into_parts();
    let method = parts.method.clone();
    let uri = handshake.local.as_ref().and_then(|local| {
        let uri = crate::uri::expand_uri_with_base(Some(local.name()), parts.uri.clone()).ok()?;
        let authority = uri.authority()?;
        (!authority.as_str().contains('@')
            && dhttp_home::normalize_name(authority.host()).as_deref() == Some(local.name()))
        .then_some(uri)
    });
    let Some(uri) = uri else {
        inbound.stop(h3x::ErrorCode::NoError.as_u64());
        let mut response = http::Response::new(
            EmptyBody::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        *response.status_mut() = http::StatusCode::MISDIRECTED_REQUEST;
        return send_response(
            response,
            method,
            scopeguard::ScopeGuard::into_inner(writer),
            qpack,
        )
        .await;
    };
    parts.uri = uri;
    let trailers = parts
        .extensions
        .remove::<h3x::Trailers>()
        .unwrap_or_default();
    parts.extensions.insert((*handshake).clone());
    let body = StreamBody::new(forward_inbound_body(inbound, trailers))
        .map_err(|error: Error| Box::new(error) as BoxError)
        .boxed_unsync();
    let request: http::Request<Body> = http::Request::from_parts(parts, body);
    let mut app = app;
    futures::future::poll_fn(|cx| app.poll_ready(cx)).await?;
    let response: std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<http::Response<Body>, BoxError>>
                + Send,
        >,
    > = app.call(request);
    let response = response.await?;
    send_response(
        response,
        method,
        scopeguard::ScopeGuard::into_inner(writer),
        qpack,
    )
    .await
}

#[cfg(test)]
#[path = "../tests/unit/endpoint.rs"]
mod tests;
