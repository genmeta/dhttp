//! Server request and response message API.
//!
//! Low-level stream access is intentionally not part of the high-level
//! request/response surface. Use `read`/`write`, buffered helpers, and
//! stream adapters instead. A future dedicated low-level API can own the raw
//! stream handles without aliasing them through these high-level wrappers.
//!
//! ```compile_fail
//! fn request_must_not_expose_raw_read_stream(
//!     request: &mut dhttp::endpoint::server::Request,
//! ) {
//!     let _ = request.read_stream();
//! }
//! ```
//!
//! ```compile_fail
//! fn response_must_not_expose_raw_write_stream(
//!     response: &mut dhttp::endpoint::server::Response,
//! ) {
//!     let _ = response.write_stream();
//! }
//! ```

use bytes::{Buf, Bytes};
use dhttp_identity::identity as agent;
use futures::{Stream, StreamExt};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::Report;
use std::sync::Arc;
use tracing::Instrument;

use crate::{
    h3x::{
        endpoint::server::UnresolvedRequest,
        error::Code,
        message::stream::{MessageStreamError, ReadStream, WriteStream},
        protocol::Protocols,
        qpack::field::Protocol,
        stream_id::StreamId,
    },
    message::{MalformedMessageError, Message, ReadToStringError},
};

pub(crate) async fn read_request_header(
    request: UnresolvedRequest,
) -> Result<(Request, Response), MessageStreamError> {
    let UnresolvedRequest {
        stream_id,
        read_stream,
        write_stream,
        connection,
    } = request;
    // Agents are backed by a watch channel — fetching them per-request
    // is effectively a clone once the handshake has completed.
    let local_agent = connection
        .local_agent()
        .await?
        .expect("server connection must have a local agent (SNI)");
    let remote_agent = connection.remote_agent().await?;
    let protocols = connection.protocols().clone();

    let mut request = Request {
        message: Message::unresolved_request(),
        stream: read_stream,
        agent: remote_agent,
        stream_id,
        protocols: protocols.clone(),
    };
    request
        .message
        .read_header_from(&mut request.stream)
        .await?;
    let response = Response {
        message: Message::unresolved_response(),
        stream: write_stream,
        agent: local_agent,
        stream_id,
        protocols,
    };
    Ok((request, response))
}

pub struct Request {
    message: Message,
    stream: ReadStream,
    agent: Option<Arc<dyn agent::RemoteAgent>>,
    stream_id: StreamId,
    protocols: Arc<Protocols>,
}

impl Request {
    pub fn method(&self) -> Method {
        self.message.header().method()
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.message.header().scheme()
    }

    pub fn authority(&self) -> Option<Authority> {
        self.message.header().authority()
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        self.message.header().path()
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.message.header().protocol()
    }

    pub fn uri(&self) -> Uri {
        self.message.header().uri()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.message.header().header_map()
    }

    pub fn header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, MessageStreamError>> {
        self.message
            .read_streaming_body_from(&mut self.stream)
            .await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, MessageStreamError> {
        self.message.read_buffered_body_from(&mut self.stream).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, MessageStreamError> {
        self.message.collect_bytes_body_from(&mut self.stream).await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.message
            .collect_string_body_from(&mut self.stream)
            .await
    }

    pub async fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        futures::stream::unfold(self, async |this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn into_stream(self) -> impl Stream<Item = Result<Bytes, MessageStreamError>> {
        futures::stream::unfold(self, async |mut this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, MessageStreamError> {
        self.message.read_trailers_from(&mut self.stream).await
    }

    pub async fn stop(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.stream.stop(code).await
    }

    pub fn agent(&self) -> Option<&Arc<dyn agent::RemoteAgent>> {
        self.agent.as_ref()
    }

    /// Returns the QUIC stream identifier for this request.
    ///
    /// The stream ID uniquely identifies the request stream within its QUIC connection.
    /// Combined with [`protocols()`](Self::protocols), it serves as the per-stream key
    /// for deriving protocol-specific session handles from connection-scoped protocol
    /// state:
    ///
    /// ```ignore
    /// let proto = request.protocols().get::<MyProtocol>().unwrap();
    /// let session = proto.create_session(request.stream_id());
    /// ```
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns the connection-scoped protocol registry.
    ///
    /// The returned `Arc<Protocols>` is shared across all request handlers on the same
    /// QUIC connection. Use [`Protocols::get`] to look up a concrete protocol runtime
    /// by type, then derive per-request handles using [`stream_id()`](Self::stream_id):
    ///
    /// ```ignore
    /// let dhttp = request.protocols().get::<DHttpProtocol>().unwrap();
    /// let qpack = request.protocols().get::<QPackProtocol>();
    /// ```
    pub fn protocols(&self) -> &Arc<Protocols> {
        &self.protocols
    }
}

pub struct Response {
    message: Message,
    stream: WriteStream,
    agent: Arc<dyn agent::LocalAgent>,
    stream_id: StreamId,
    protocols: Arc<Protocols>,
}

impl Response {
    fn check_message_operation(
        &mut self,
        operation: &str,
        operate: impl FnOnce(&mut Self) -> Result<(), MalformedMessageError>,
    ) -> bool {
        if self.message.is_malformed() {
            tracing::warn!(
                operation,
                "response is malformed, operation will not affect the response stream",
            );
            return false;
        }
        if let Err(error) = operate(self) {
            let report = Report::from_error(&error);
            tracing::warn!(
                operation, error = %report,
                "operation malformed the response message, response stream will be cancelled",
            );
            self.message.set_malformed();
            return false;
        }
        true
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.message.header().header_map()
    }

    pub fn headers_mut(&mut self) -> &mut http::HeaderMap {
        self.check_message_operation("modify_headers", |this| {
            this.message.header_mut().map(|_| ())
        });
        self.message.header_mut_unchecked().header_map_mut()
    }

    pub fn set_header(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.headers_mut().insert(name, value);
        self
    }

    pub fn status(&self) -> Option<http::StatusCode> {
        Some(self.message.header().status())
    }

    pub fn set_status(&mut self, status: http::StatusCode) -> &mut Self {
        self.check_message_operation("set_status", |this| {
            this.message.header_mut()?.set_status(status);
            Ok(())
        });
        self
    }

    pub fn set_body(&mut self, content: impl Buf) -> &mut Self {
        self.check_message_operation("write_chunked_body", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            this.message.set_body(content)?;
            Ok(())
        });
        self
    }

    pub async fn write(
        &mut self,
        content: impl Buf + Send,
    ) -> Result<&mut Self, MessageStreamError> {
        self.check_message_operation("write_streaming_body", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            this.message.streaming_body()?;
            Ok(())
        });
        self.message
            .write_streaming_body_to(&mut self.stream, content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, MessageStreamError> {
        self.check_message_operation("flush_response", |this| {
            if !this.message.header().is_empty() {
                this.message.header().check_pseudo()?;
            }
            Ok(())
        });
        self.message.write_all_to(&mut self.stream).await?;
        self.stream.flush().await?;
        Ok(self)
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.message.trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.check_message_operation("modify_trailers", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            this.message.trailers_mut().map(|_| ())
        });
        self.message.trailers_mut_unchecked()
    }

    pub fn set_trailer(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.trailers_mut().insert(name, value);
        self
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> &mut Self {
        *self.trailers_mut() = map;
        self
    }

    pub async fn close(&mut self) -> Result<(), MessageStreamError> {
        self.check_message_operation("close_response", |this| {
            this.message.header().check_pseudo()?;
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::FinalResponseRequired);
            }
            Ok(())
        });
        async {
            self.message.write_all_to(&mut self.stream).await?;
            self.stream.close().await
        }
        .await
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.stream.cancel(code).await
    }

    pub fn agent(&self) -> &Arc<dyn agent::LocalAgent> {
        &self.agent
    }

    /// Returns the QUIC stream identifier for this response.
    ///
    /// Same stream ID as the corresponding [`Request::stream_id`]. Useful when the
    /// response handler needs to interact with connection-scoped protocols:
    ///
    /// ```ignore
    /// let proto = response.protocols().get::<MyProtocol>().unwrap();
    /// let session = proto.create_session(response.stream_id());
    /// ```
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns the connection-scoped protocol registry.
    ///
    /// Same `Arc<Protocols>` as [`Request::protocols`]. See [`Protocols::get`] for
    /// typed protocol lookup.
    pub fn protocols(&self) -> &Arc<Protocols> {
        &self.protocols
    }

    /// Async drop the response properly
    pub(crate) fn drop(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if self.message.is_complete() || self.message.is_dropped() {
            return None;
        }
        // It's ok to take: Response will not be used after drop
        let mut stream = self.stream.take();
        let mut message = self.message.take();

        if !message.is_malformed() {
            let check = || {
                message.header().check_pseudo()?;
                if message.is_interim_response() {
                    return Err(MalformedMessageError::FinalResponseRequired);
                }
                Ok(())
            };
            if let Err(error) = check() {
                message.set_malformed();
                let report = Report::from_error(&error);
                tracing::warn!(
                    error = %report,
                    "response stream cannot be closed properly as it is malformed",
                );
            }
        }

        Some(async move {
            _ = async {
                message.write_all_to(&mut stream).await?;
                stream.close().await
            }
            .await;
        })
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(future) = self.drop() {
            // Best-effort: send the end-of-stream marker before the response is dropped.
            tokio::spawn(future.in_current_span());
        }
    }
}
