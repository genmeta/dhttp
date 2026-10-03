use super::Endpoint;
use crate::{Body, RequestFuture, Result, network::DhttpNetwork};
use bytes::Bytes;
use h3x::{ReadResponse, Trailers, WndBuf, WriteRequest};
use qrecovery::send::CancelStream;
use std::{
    fmt,
    future::{Future, IntoFuture},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{io::AsyncWrite, task::JoinHandle};

/// An empty request body.
pub type Empty = http_body_util::Empty<Bytes>;

pub(super) const REQUEST_WINDOW_BYTES: usize = 64 * 1024;

/// A request accepted by h3x, bound to its outbound endpoint.
/// Awaiting `Request<Empty>` returns the response. Awaiting `Request<WndBuf>`
/// consumes the request and returns a [`RequestWriter`] and a response future.
#[must_use = "configure and await the request to send it"]
pub struct Request<B = Empty> {
    pub(super) endpoint: Endpoint,
    pub(super) message: http::Request<B>,
}

impl<B: fmt::Debug> fmt::Debug for Request<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("endpoint", &self.endpoint.name())
            .field("message", &self.message)
            .finish()
    }
}

impl<B> Request<B> {
    pub(super) fn bound(endpoint: Endpoint, message: http::Request<B>) -> Self {
        Self { endpoint, message }
    }

    /// Construct an anonymous outbound request with `Empty` or `WndBuf` as its body.
    /// The server's identity is still verified.
    pub fn new(message: http::Request<B>) -> Self {
        Endpoint::new(None).from_request(message)
    }

    /// Set a header before sending the request.
    pub fn header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().insert(name, value);
        self
    }

    /// Append a header before sending the request.
    pub fn append_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().append(name, value);
        self
    }

    /// Set a trailer before sending, replacing any values with the same name.
    /// Trailers are sent automatically when the request body ends.
    pub fn trailer(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message
            .extensions_mut()
            .get_or_insert_default::<Trailers>()
            .set(name, value);
        self
    }

    /// Append a trailer before sending without replacing existing values.
    pub fn append_trailer(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message
            .extensions_mut()
            .get_or_insert_default::<Trailers>()
            .append(name, value);
        self
    }

    /// Replace the body before sending. Use `Empty` or a `WndBuf`.
    /// A window body stays open until the returned writer is shut down.
    pub fn body<T>(self, body: T) -> Request<T> {
        Request {
            endpoint: self.endpoint,
            message: self.message.map(|_| body),
        }
    }

    /// Set initial bytes before sending, leaving input open for further writes.
    pub fn write(self, data: impl AsRef<[u8]>) -> Request<WndBuf> {
        self.body(WndBuf::with_initial(
            REQUEST_WINDOW_BYTES,
            Bytes::copy_from_slice(data.as_ref()),
        ))
    }

    async fn connect(&mut self) -> Result<h3x::H3Connection<crate::transport::QuicTransport>> {
        let (uri, remote) =
            crate::uri::resolve_request_uri(self.endpoint.name(), self.message.uri().clone())?;
        *self.message.uri_mut() = uri;
        let network = DhttpNetwork::global()?;
        network
            .get_connection(self.endpoint.clone(), Arc::from(remote))
            .await
    }
}

impl IntoFuture for Request<Empty> {
    type Output = Result<http::Response<Body>>;
    type IntoFuture = RequestFuture;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            let h3 = self.connect().await?;
            let (writer, reader) = h3.open_bi().await?;
            let mut response =
                send_empty_request(self.message, writer, reader, h3.qpack().clone()).await?;
            if let Some(peer) = h3.transport().handshake.remote.clone() {
                response.extensions_mut().insert(peer);
            }
            Ok(response)
        })
    }
}

impl IntoFuture for Request<WndBuf> {
    type Output = Result<(RequestWriter, RequestFuture)>;
    type IntoFuture = RequestFuture<(RequestWriter, RequestFuture)>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            let h3 = self.connect().await?;
            let peer = h3.transport().handshake.remote.clone();
            let (writer, reader) = h3.open_bi().await?;
            let (request, response) =
                send_request(self.message, writer, reader, h3.qpack().clone());
            let response: RequestFuture = Box::pin(async move {
                let mut response = response.await?;
                if let Some(peer) = peer {
                    response.extensions_mut().insert(peer);
                }
                Ok(response)
            });
            Ok((request, response))
        })
    }
}

pub(super) fn send_empty_request<W, R>(
    message: http::Request<Empty>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
) -> impl Future<Output = Result<http::Response<Body>>> + Send
where
    W: WriteRequest<Empty> + 'static,
    R: ReadResponse + 'static,
{
    let method = message.method().clone();
    let writing = writer.write_request(message, qpack.clone());
    let sending = async move {
        match writing.await {
            // A peer can decline an empty request and still send a valid response.
            Err(h3x::Error::Stream(detail)) if detail.code == h3x::ErrorCode::NoError => Ok(()),
            result => result,
        }
    };
    let reading = reader.read_response(method, qpack);
    async move {
        let ((), response) = tokio::try_join!(sending, reading)?;
        Ok(response)
    }
}

/// The write direction of a request that has started sending.
/// Use `AsyncWriteExt::shutdown` to send EOF or [`CancelStream::cancel`] to reset it.
/// Trailers can be changed until shutdown starts and are sent after all data.
/// Dropping this handle cancels unfinished uploading.
/// Headers and body configuration are only available before sending:
///
/// ```compile_fail,E0599
/// async fn send(endpoint: &dhttp::Endpoint, uri: dhttp::Uri) -> dhttp::Result<()> {
///     let (writer, _) = endpoint.post(uri).await?;
///     writer.header(
///         dhttp::HeaderName::from_static("x-example"),
///         dhttp::HeaderValue::from_static("changed"),
///     );
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[must_use = "keep the writer until uploading finishes; dropping it cancels unfinished uploading"]
pub struct RequestWriter {
    body: WndBuf,
    trailers: Trailers,
    closed: bool,
    upload: Option<JoinHandle<h3x::Result<()>>>,
}

impl RequestWriter {
    /// Set a trailer, replacing any values with the same name.
    /// Returns BrokenPipe after shutdown starts, cancellation, or upload completion.
    pub fn trailer(&mut self, name: http::HeaderName, value: http::HeaderValue) -> io::Result<()> {
        self.ensure_open()?;
        self.trailers.set(name, value);
        Ok(())
    }

    /// Append a trailer without replacing existing values.
    /// Returns BrokenPipe after shutdown starts, cancellation, or upload completion.
    pub fn append_trailer(
        &mut self,
        name: http::HeaderName,
        value: http::HeaderValue,
    ) -> io::Result<()> {
        self.ensure_open()?;
        self.trailers.append(name, value);
        Ok(())
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.closed || self.upload.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

impl CancelStream for RequestWriter {
    fn cancel(&mut self, error_code: u64) {
        self.closed = true;
        if let Some(upload) = &self.upload
            && !upload.is_finished()
        {
            // Reset the shared window before aborting so h3x sees the requested code.
            self.body.cancel(error_code);
            upload.abort();
        }
    }
}

impl Drop for RequestWriter {
    fn drop(&mut self) {
        self.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
    }
}

impl AsyncWrite for RequestWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut this.body).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().body).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Freeze trailers before publishing EOF, including while shutdown is Pending.
        this.closed = true;
        ready!(Pin::new(&mut this.body).poll_shutdown(cx))?;
        let Some(upload) = &mut this.upload else {
            return Poll::Ready(Ok(()));
        };
        // Keep ownership while Pending so cancelling shutdown() cannot detach the task.
        let result = ready!(Pin::new(upload).poll(cx));
        this.upload.take();
        Poll::Ready(match result {
            Ok(result) => result.map_err(io::Error::from),
            Err(error) => Err(io::Error::other(error)),
        })
    }
}

pub(super) fn send_request<W, R>(
    mut message: http::Request<WndBuf>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
) -> (RequestWriter, RequestFuture)
where
    W: WriteRequest<WndBuf> + 'static,
    R: ReadResponse + 'static,
{
    let method = message.method().clone();
    let trailers = message
        .extensions_mut()
        .get_or_insert_default::<Trailers>()
        .clone();
    let mut body = message.body().clone();
    let upload = tokio::spawn(writer.write_request(message, qpack.clone()));
    let abort = upload.abort_handle();
    let request = RequestWriter {
        body: body.clone(),
        trailers,
        closed: false,
        upload: Some(upload),
    };
    let reading = reader.read_response(method, qpack);
    let response: RequestFuture = Box::pin(async move {
        reading.await.map_err(|error| {
            body.cancel(error.code.as_u64());
            abort.abort();
            error.into()
        })
    });
    (request, response)
}
