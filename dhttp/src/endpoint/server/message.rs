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
use snafu::{OptionExt, Report, ResultExt, Snafu};
use std::{future::Future, sync::Arc};
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
    message::{
        Body, IntoBody, MalformedMessageError, ReadToStringError, RequestMessage, ResponseMessage,
    },
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ResolveError {
    #[snafu(display("failed to read server local agent"))]
    LocalAgent {
        source: crate::h3x::quic::ConnectionError,
    },
    #[snafu(display("server request is missing local agent"))]
    MissingLocalAgent,
    #[snafu(display("failed to read server remote agent"))]
    RemoteAgent {
        source: crate::h3x::quic::ConnectionError,
    },
    #[snafu(display("failed to read request header"))]
    ReadHeader { source: MessageStreamError },
}

pub async fn resolve(request: UnresolvedRequest) -> Result<(Request, Response), ResolveError> {
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
        .await
        .context(resolve_error::LocalAgentSnafu)?
        .context(resolve_error::MissingLocalAgentSnafu)?;
    let remote_agent = connection
        .remote_agent()
        .await
        .context(resolve_error::RemoteAgentSnafu)?;
    let protocols = connection.protocols().clone();

    let mut read_stream = read_stream;
    let request_message = RequestMessage::read_from(&mut read_stream)
        .await
        .context(resolve_error::ReadHeaderSnafu)?;
    let request = Request {
        message: request_message,
        stream: read_stream,
        agent: remote_agent,
        stream_id,
        protocols: protocols.clone(),
    };
    let response = Response {
        message: Some(ResponseMessage::default()),
        stream: Some(write_stream),
        agent: local_agent,
        stream_id,
        protocols,
    };
    Ok((request, response))
}

pub struct Request {
    message: RequestMessage,
    stream: ReadStream,
    agent: Option<Arc<dyn agent::RemoteAgent>>,
    stream_id: StreamId,
    protocols: Arc<Protocols>,
}

impl Request {
    pub fn method(&self) -> Method {
        self.message.method().clone()
    }

    pub fn scheme(&self) -> Option<Scheme> {
        Some(self.message.header().scheme().clone())
    }

    pub fn authority(&self) -> Option<Authority> {
        Some(self.message.header().authority().clone())
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        Some(self.message.header().path().clone())
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.message.header().protocol().cloned()
    }

    pub fn uri(&self) -> Uri {
        self.message.uri()
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
    message: Option<ResponseMessage>,
    stream: Option<WriteStream>,
    agent: Arc<dyn agent::LocalAgent>,
    stream_id: StreamId,
    protocols: Arc<Protocols>,
}

impl Response {
    fn check_message_operation(
        &mut self,
        operation: &str,
        operate: impl FnOnce(&mut ResponseMessage) -> Result<(), MalformedMessageError>,
    ) -> bool {
        if self.message.is_none() || self.stream.is_none() {
            tracing::warn!(
                operation,
                "response is already finalized, operation will not affect the response stream",
            );
            return false;
        }
        let message = self
            .message
            .as_mut()
            .expect("response message is present after explicit check");
        if let Err(error) = operate(message) {
            let report = Report::from_error(&error);
            tracing::warn!(
                operation, error = %report,
                "response message operation failed, operation will not affect the response stream",
            );
            return false;
        }
        true
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.message
            .as_ref()
            .expect("response message is unavailable after finalization")
            .header()
            .header_map()
    }

    pub fn headers_mut(&mut self) -> &mut http::HeaderMap {
        self.check_message_operation("modify_headers", |message| message.header_mut().map(|_| ()));
        self.message
            .as_mut()
            .expect("response message is unavailable after finalization")
            .header_mut_unchecked()
            .header_map_mut()
    }

    pub fn set_header(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.check_message_operation("set_header", |message| {
            message.header_mut()?.header_map_mut().insert(name, value);
            Ok(())
        });
        self
    }

    pub fn status(&self) -> Option<http::StatusCode> {
        self.message.as_ref().map(ResponseMessage::status)
    }

    pub fn set_status(&mut self, status: http::StatusCode) -> &mut Self {
        self.check_message_operation("set_status", |message| {
            message.header_mut()?.set_status(status);
            Ok(())
        });
        self
    }

    pub fn set_body(&mut self, content: impl IntoBody) -> &mut Self {
        self.check_message_operation("write_chunked_body", |message| {
            if message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            message.set_body(content)?;
            Ok(())
        });
        self
    }

    pub fn write<B>(
        &mut self,
        content: B,
    ) -> impl Future<Output = Result<&mut Self, MessageStreamError>> + use<'_, B>
    where
        B: IntoBody,
    {
        let content: Body = content.into_body();
        async move {
            if !self.check_message_operation("write_streaming_body", |message| {
                if message.is_interim_response() {
                    return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
                }
                message.streaming_body()?;
                Ok(())
            }) {
                return Err(MessageStreamError::MessageSendFailed);
            }
            let message = self
                .message
                .as_mut()
                .ok_or(MessageStreamError::MessageSendFailed)?;
            let stream = self
                .stream
                .as_mut()
                .ok_or(MessageStreamError::MessageSendFailed)?;
            message.write_streaming_body_to(stream, content).await?;
            Ok(self)
        }
    }

    pub async fn flush(&mut self) -> Result<&mut Self, MessageStreamError> {
        let message = self
            .message
            .as_mut()
            .ok_or(MessageStreamError::MessageSendFailed)?;
        let stream = self
            .stream
            .as_mut()
            .ok_or(MessageStreamError::MessageSendFailed)?;
        message.write_all_to(stream).await?;
        stream.flush().await?;
        Ok(self)
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.message
            .as_ref()
            .expect("response message is unavailable after finalization")
            .trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.check_message_operation("modify_trailers", |message| {
            if message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            message.trailers_mut().map(|_| ())
        });
        self.message
            .as_mut()
            .expect("response message is unavailable after finalization")
            .trailers_mut_unchecked()
    }

    pub fn set_trailer(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.check_message_operation("set_trailer", |message| {
            if message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            message.trailers_mut()?.insert(name, value);
            Ok(())
        });
        self
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> &mut Self {
        self.check_message_operation("set_trailers", |message| {
            if message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            *message.trailers_mut()? = map;
            Ok(())
        });
        self
    }

    pub async fn close(&mut self) -> Result<(), MessageStreamError> {
        if let Some(future) = self.finish() {
            future.await
        } else {
            Ok(())
        }
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.message = None;
        if let Some(mut stream) = self.stream.take() {
            stream.cancel(code).await
        } else {
            Ok(())
        }
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

    /// Returns a future that completes response finalization, if the response is unfinished.
    ///
    /// Awaiting the returned future writes any buffered response data and closes the response
    /// stream. If this method returns `None`, the response has already been completed or
    /// finalized. Dropping an unfinished response still performs the same finalization in a
    /// best-effort background task.
    pub fn finish(
        &mut self,
    ) -> Option<impl Future<Output = Result<(), MessageStreamError>> + Send + use<>> {
        let mut message = self.message.take()?;
        let mut stream = self
            .stream
            .take()
            .expect("response stream is unavailable while message is unfinished");

        Some(async move {
            if message.is_interim_response() {
                let error = MalformedMessageError::FinalResponseRequired;
                let report = Report::from_error(&error);
                tracing::warn!(
                    error = %report,
                    "response stream cannot be closed without a final response",
                );
                _ = stream.cancel(Code::H3_MESSAGE_ERROR).await;
                return Err(MessageStreamError::MessageSendFailed);
            }

            message.write_all_to(&mut stream).await?;
            stream.close().await
        })
    }

    /// Async drop the response properly.
    pub(crate) fn drop(
        &mut self,
    ) -> Option<impl Future<Output = Result<(), MessageStreamError>> + Send + use<>> {
        self.finish()
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(future) = self.finish() {
            // Inherent termination: the task owns the response message and stream,
            // then exits after writing/canceling and closing the stream.
            tokio::spawn(
                async move {
                    if let Err(error) = future.await {
                        let report = Report::from_error(&error);
                        tracing::debug!(error = %report, "failed to finish response on drop");
                    }
                }
                .in_current_span(),
            );
        }
    }
}
