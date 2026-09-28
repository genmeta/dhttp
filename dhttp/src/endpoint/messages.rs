use super::*;
use qrecovery::{recv::StopSending, send::CancelStream};
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
                dhttp_home::resolve_request_uri(self.endpoint.name(), message.uri().clone())?;
            *message.uri_mut() = uri;
            let network = DhttpNetwork::global()?;
            let h3 = network
                .get_connection(self.endpoint.name.clone(), Arc::from(remote))
                .await?;
            let (writer, reader) = h3.open_bi().await.map_err(h3_error)?;
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
    let send_qpack = qpack.clone();
    let mut reset = outgoing.clone();
    let trailers = outgoing.clone();
    let upload = tokio::spawn(write_with_body(
        body,
        buffer,
        async move {
            writer
                .write_request(outgoing, send_qpack)
                .await
                .map_err(h3_error)
        },
        move |name, value| {
            trailers.append_trailer(name, value);
        },
        move || reset.cancel(h3x::ErrorCode::RequestCancelled.as_u64()),
    ));
    let upload = scopeguard::guard(upload, |task| task.abort());

    // Response headers can arrive before the request body finishes uploading.
    let response = reader
        .read_response(method, qpack)
        .await
        .map_err(h3_error)?;

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
        let _ = scopeguard::ScopeGuard::into_inner(upload);
    };
    let body = StreamBody::new(stream)
        .map_err(|error: Error| Box::new(error) as BoxError)
        .boxed_unsync();
    Ok(http::Response::from_parts(parts, body))
}

// Expose the receive window as a pull-based stream of standard HTTP body frames.
pub(super) fn forward_inbound_body(
    inbound: h3x::ArcWndBuf,
    trailers: h3x::Trailers,
) -> impl futures::Stream<Item = Result<Frame<Bytes>>> + Send {
    let inbound = scopeguard::guard(inbound, |mut inbound| {
        inbound.stop(h3x::ErrorCode::NoError.as_u64());
    });
    async_stream::try_stream! {
        let inbound = inbound;
        loop {
            let bytes = inbound.read_chunk(BODY_READ_CHUNK_BYTES).await.map_err(io_error)?;
            if bytes.is_empty() { break; }
            yield Frame::data(bytes);
        }
        let _ = scopeguard::ScopeGuard::into_inner(inbound);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    }
}

async fn write_with_body<B, F>(
    body: B,
    buffer: h3x::ArcWndBuf,
    writing: F,
    trailer: impl FnMut(http::HeaderName, http::HeaderValue),
    mut reset: impl FnMut(),
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
    F: std::future::Future<Output = Result<()>>,
{
    let forwarding = async move {
        let result = forward_outbound_body(body, buffer, trailer).await;
        // A local Body error has no transport error until this direction is reset.
        if matches!(&result, Err(Error::Io { .. })) {
            reset();
        }
        result
    };
    // h3x propagates write-direction failures to the corresponding read direction.
    tokio::try_join!(biased; writing, forwarding).map(|_| ())
}

async fn forward_outbound_body<B>(
    src: B,
    mut dst: h3x::ArcWndBuf,
    mut trailer: impl FnMut(http::HeaderName, http::HeaderValue),
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let mut body = Box::pin(src);
    loop {
        let frame: Option<std::result::Result<Frame<Bytes>, BoxError>> =
            body.frame().await.map(|frame| frame.map_err(Into::into));
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(box_error)?;
        match frame.into_data() {
            Ok(data) => {
                dst.write_bytes(data)
                    .await
                    .map_err(h3x::Error::from_stream_io)
                    .map_err(h3_error)?;
            }
            Err(frame) => {
                if let Ok(fields) = frame.into_trailers() {
                    // HeaderMap's borrowed iterator emits the name for every value.
                    for (name, value) in fields.iter() {
                        trailer(name.clone(), value.clone());
                    }
                }
            }
        }
    }
    dst.shutdown()
        .await
        .map_err(h3x::Error::from_stream_io)
        .map_err(h3_error)
}

pub(super) fn send_response<B, W>(
    response: http::Response<B>,
    method: http::Method,
    writer: W,
    qpack: h3x::ArcQpack,
) -> impl std::future::Future<Output = Result<()>>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
    W: WriteResponse,
{
    async move {
        let (parts, body) = response.into_parts();
        let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
        let outgoing = h3x::Response::<h3x::W>::from_parts(parts, buffer.clone());
        // Do not poll an application Body that h3x will suppress on the wire.
        if method == http::Method::HEAD
            || outgoing.status() == http::StatusCode::NO_CONTENT
            || outgoing.status() == http::StatusCode::NOT_MODIFIED
        {
            drop(body);
            let result = writer
                .write_response(outgoing, method, qpack)
                .await
                .map_err(h3_error);
            return match result {
                Err(Error::Http3 { source }) if source.code == h3x::ErrorCode::NoError => Ok(()),
                result => result,
            };
        }
        let mut reset = outgoing.clone();
        let trailers = outgoing.clone();
        let result = write_with_body(
            body,
            buffer,
            async move {
                writer
                    .write_response(outgoing, method, qpack)
                    .await
                    .map_err(h3_error)
            },
            move |name, value| {
                trailers.append_trailer(name, value);
            },
            move || reset.cancel(h3x::ErrorCode::RequestCancelled.as_u64()),
        )
        .await;
        match result {
            Ok(_) => Ok(()),
            // The peer can decline the rest of a response body without failing the exchange.
            Err(Error::Http3 { source }) if source.code == h3x::ErrorCode::NoError => Ok(()),
            Err(error) => Err(error),
        }
    }
}
