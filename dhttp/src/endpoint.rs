//! Identity-bound request and response handling.
use crate::{Body, BoxError, EmptyBody, Error, RequestFuture, Result, network::DhttpNetwork};
use bytes::Bytes;
use h3x::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use qconn::Scopes;
use qrecovery::{recv::StopSending, send::CancelStream};
use std::{future::IntoFuture, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use tower_service::Service;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(16 * 60);
const BODY_WINDOW_BYTES: usize = 64 * 1024;
const BODY_READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

#[must_use = "configure and await the request to send it"]
pub struct Request<B> {
    endpoint: Endpoint,
    message: http::Request<B>,
}

mod messages;
use messages::{receiving_body, send_response};
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

    pub fn stop_listening(&self) -> Result<()> {
        DhttpNetwork::global()?.stop_listening(&self.name);
        Ok(())
    }
}

pub async fn resolve_remote(endpoint: &Endpoint, name: &str) -> Result<qtls::RemoteAuthority> {
    DhttpNetwork::global()?
        .resolve_remote(endpoint.name.clone(), name)
        .await
}

pub(crate) fn h3_error(source: h3x::Error) -> Error {
    Error::Http3 {
        source: Arc::new(source),
    }
}
pub(crate) fn io_error(source: impl Into<BoxError>) -> Error {
    Error::Io {
        source: Arc::new(std::io::Error::other(source.into())),
    }
}
fn box_error(source: BoxError) -> Error {
    Error::Io {
        source: Arc::new(std::io::Error::other(source)),
    }
}

pub(crate) fn serve_exchange<W, R>(
    app: crate::network::ErasedService,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
    handshake: Arc<qtls::HandshakeSummary>,
) -> impl std::future::Future<Output = Result<()>>
where
    W: WriteResponse + CancelStream,
    R: ReadRequest,
{
    // Establish cancellation ownership before the future is polled.
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    async move {
        let reading = reader.read_request(qpack.clone());
        tokio::pin!(reading);
        let writer = writer;
        let incoming = tokio::time::timeout(OPERATION_TIMEOUT, &mut reading)
            .await
            .map_err(io_error)?
            .map_err(h3_error)?;
        let (mut parts, inbound) = incoming.into_parts();
        let method = parts.method.clone();
        let trailers = parts
            .extensions
            .remove::<h3x::Trailers>()
            .unwrap_or_default();
        parts.extensions.insert((*handshake).clone());
        let body = receiving_body(inbound, trailers, h3x::ErrorCode::NoError);
        let request: http::Request<Body> = http::Request::from_parts(parts, body);
        let mut app = app;
        futures::future::poll_fn(|cx| app.poll_ready(cx))
            .await
            .map_err(box_error)?;
        let response: std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<http::Response<Body>, BoxError>,
                    > + Send,
            >,
        > = app.call(request);
        let response = response.await.map_err(box_error)?;
        send_response(
            response,
            method,
            scopeguard::ScopeGuard::into_inner(writer),
            qpack,
        )
        .await
    }
}

#[cfg(test)]
#[path = "../tests/unit/endpoint.rs"]
mod tests;
