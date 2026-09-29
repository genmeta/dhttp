use super::{
    BODY_WINDOW_BYTES, Request,
    body::{forward_inbound_body, forward_outbound_body},
};
use crate::{Body, BoxError, Error, RequestFuture, Result, network::DhttpNetwork};
use bytes::Bytes;
use futures::StreamExt;
use h3x::{ReadResponse, WriteRequest};
use http_body_util::{BodyExt, StreamBody};
use std::{future::IntoFuture, sync::Arc};

impl<B> Request<B> {
    pub fn header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().insert(name, value);
        self
    }

    pub fn append_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().append(name, value);
        self
    }

    pub fn body<T>(self, body: T) -> Request<T> {
        let (parts, _) = self.message.into_parts();
        Request {
            endpoint: self.endpoint,
            message: http::Request::from_parts(parts, body),
        }
    }
}

impl<B> IntoFuture for Request<B>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Output = Result<http::Response<Body>>;
    type IntoFuture = RequestFuture;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut message = self.message;
            let (uri, remote) =
                crate::uri::resolve_request_uri(self.endpoint.name(), message.uri().clone())?;
            *message.uri_mut() = uri;
            let network = DhttpNetwork::global()?;
            let h3 = network
                .get_connection(self.endpoint.name.clone(), Arc::from(remote))
                .await?;
            let (writer, reader) = h3.open_bi().await?;
            send_request(message, writer, reader, h3.qpack().clone()).await
        })
    }
}

pub(super) async fn send_request<B, W, R>(
    message: http::Request<B>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
) -> Result<http::Response<Body>>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    W: WriteRequest + 'static,
    R: ReadResponse,
{
    let method = message.method().clone();
    let (parts, body) = message.into_parts();
    let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
    let outgoing = h3x::Request::<h3x::W>::from_parts(parts, buffer.clone());
    let trailers = outgoing.clone();
    let send_qpack = qpack.clone();
    let write_request = tokio::spawn(async move {
        let writing = async move {
            writer
                .write_request(outgoing, send_qpack)
                .await
                .map_err(Error::from)
        };
        let forwarding = forward_outbound_body(body, buffer, move |name, value| {
            trailers.append_trailer(name, value);
        });
        tokio::try_join!(biased; writing, forwarding).map(|_| ())
    });
    let upload = scopeguard::guard(write_request, |task| task.abort());

    // Response headers can arrive before the request body finishes uploading.
    let response = reader.read_response(method, qpack).await?;

    let (mut parts, inbound) = response.into_parts();
    let trailers = parts
        .extensions
        .remove::<h3x::Trailers>()
        .unwrap_or_default();
    let inbound_frames = forward_inbound_body(inbound, trailers);
    let stream = async_stream::try_stream! {
        tokio::pin!(inbound_frames);
        while let Some(frame) = inbound_frames.next().await {
            yield frame?;
        }
        // A complete response releases ownership without interrupting an active upload.
        scopeguard::ScopeGuard::into_inner(upload);
    };
    let body = StreamBody::new(stream)
        .map_err(|error: Error| Box::new(error) as BoxError)
        .boxed_unsync();
    Ok(http::Response::from_parts(parts, body))
}
