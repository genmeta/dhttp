//! Client endpoint API.
//!
//! Low-level stream access is intentionally not part of the high-level
//! response surface. Streaming is exposed through `read`, `read_all`,
//! `read_to_bytes`, `read_to_string`, `as_stream`, and `into_stream`.
//!
//! ```compile_fail
//! fn response_must_not_expose_raw_read_stream(
//!     response: &mut dhttp::endpoint::client::Response,
//! ) {
//!     let _ = response.read_stream();
//! }
//! ```

use std::{
    future::{Future, IntoFuture},
    ops::ControlFlow,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, Bytes};
use dhttp_identity::identity as agent;
use futures::{Stream, StreamExt, future::BoxFuture};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::Authority,
};
use snafu::{Report, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    endpoint::client::request_error::StreamInitSnafu,
    h3x::{
        error::Code,
        message::stream::{InitialMessageStreamError, MessageStreamError, ReadStream, WriteStream},
        pool::ConnectError,
        qpack::field::MalformedHeaderSection,
        quic,
    },
    message::{
        Body, IntoBody, IntoUri, IntoUriError, MalformedMessageError, Message, MessageWriteGoal,
        ReadToStringError,
    },
};

type DquicH3Endpoint = crate::h3x::dquic::H3Endpoint;
type DquicConnectError = crate::dquic::ConnectError;
type RequestInitResult = Result<(), RequestError>;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MalformedRequestError {
    #[snafu(display("failed to convert request uri"))]
    Uri { source: IntoUriError },
    #[snafu(display("request authority is frozen"))]
    AuthorityFrozen { source: AuthorityFrozen },
    #[snafu(display("request message operation `{operation}` failed"))]
    MessageOperation {
        operation: &'static str,
        source: MalformedMessageError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestError {
    #[snafu(display("failed to connect endpoint"))]
    Connect {
        source: Arc<ConnectError<DquicConnectError>>,
    },
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(display("request stream error"))]
    RequestStream { source: quic::StreamError },
    #[snafu(display("response stream error"))]
    ResponseStream { source: quic::StreamError },
    #[snafu(display("request cannot be sent due to malformed header"))]
    MalformedRequestHeader { source: Arc<MalformedHeaderSection> },
    #[snafu(display("request cannot be sent because it is malformed"))]
    MalformedRequest { source: Arc<MalformedRequestError> },
    #[snafu(display(
        "header section too large to fit into a single frame, maybe too many header fields"
    ))]
    HeaderTooLarge,
    #[snafu(display(
        "trailer section too large to fit into a single frame, maybe too many header fields"
    ))]
    TrailerTooLarge,
    #[snafu(display("data frame payload too large, try smaller chunk size"))]
    DataFrameTooLarge,
    #[snafu(display("response from peer is malformed"))]
    MalformedResponse,
    #[snafu(transparent)]
    Acquire { source: AcquireError },
    #[snafu(display("failed to open initial message stream"))]
    StreamInit { source: InitialMessageStreamError },
    #[snafu(transparent)]
    MessageStream { source: MessageStreamError },
}

impl From<ConnectError<DquicConnectError>> for RequestError {
    fn from(source: ConnectError<DquicConnectError>) -> Self {
        Self::Connect {
            source: Arc::new(source),
        }
    }
}
impl Clone for RequestError {
    fn clone(&self) -> Self {
        match self {
            Self::Connect { source } => Self::Connect {
                source: Arc::clone(source),
            },
            Self::Connection { source } => Self::Connection {
                source: source.clone(),
            },
            Self::RequestStream { source } => Self::RequestStream {
                source: source.clone(),
            },
            Self::ResponseStream { source } => Self::ResponseStream {
                source: source.clone(),
            },
            Self::MalformedRequestHeader { source } => Self::MalformedRequestHeader {
                source: Arc::clone(source),
            },
            Self::MalformedRequest { source } => Self::MalformedRequest {
                source: Arc::clone(source),
            },
            Self::HeaderTooLarge => Self::HeaderTooLarge,
            Self::TrailerTooLarge => Self::TrailerTooLarge,
            Self::DataFrameTooLarge => Self::DataFrameTooLarge,
            Self::MalformedResponse => Self::MalformedResponse,
            Self::Acquire { source } => Self::Acquire {
                source: source.clone(),
            },
            Self::StreamInit { source } => Self::StreamInit {
                source: source.clone(),
            },
            Self::MessageStream { source } => Self::MessageStream {
                source: source.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum AcquireError {
    #[snafu(display("resource already taken by another clone"))]
    AlreadyTaken,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AuthorityFrozen {
    #[snafu(display("authority is frozen — uri() called after stream initialization"))]
    InitComplete,
}

pub(crate) struct RequestState {
    message: SyncMutex<Message>,
    write_stream: AsyncMutex<Option<WriteStream>>,
    read_stream: AsyncMutex<Option<ReadStream>>,
    // Shared result slot for both synchronous request construction failures and
    // asynchronous stream initialization. Synchronous setters cannot await, so
    // `init_lock` only serializes the async initialization path.
    init_state: SyncMutex<Option<RequestInitResult>>,
    init_lock: AsyncMutex<()>,
    endpoint: Arc<DquicH3Endpoint>,
    authority: SyncMutex<Option<Authority>>,
    init_frozen: AtomicBool,
}

impl RequestState {
    pub(crate) fn new(endpoint: Arc<DquicH3Endpoint>, message: Message) -> Self {
        Self {
            message: SyncMutex::new(message),
            write_stream: AsyncMutex::new(None),
            read_stream: AsyncMutex::new(None),
            init_state: SyncMutex::new(None),
            init_lock: AsyncMutex::new(()),
            endpoint,
            authority: SyncMutex::new(None),
            init_frozen: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_authority(&self, auth: Authority) -> Result<(), AuthorityFrozen> {
        if self.init_frozen.load(Ordering::Acquire) {
            return Err(AuthorityFrozen::InitComplete);
        }
        *self.authority.lock().expect("lock poisoned") = Some(auth);
        Ok(())
    }

    fn message(&self) -> std::sync::MutexGuard<'_, Message> {
        self.message.lock().expect("lock poisoned")
    }

    fn mark_message_failed_unless_malformed(&self) {
        let mut message = self.message();
        if !message.is_malformed() {
            message.set_failed();
        }
    }

    fn init_result(&self) -> Option<RequestInitResult> {
        self.init_state.lock().expect("lock poisoned").clone()
    }

    fn init_result_or_start_init(&self) -> Option<RequestInitResult> {
        let guard = self.init_state.lock().expect("lock poisoned");
        if let Some(result) = guard.as_ref() {
            return Some(result.clone());
        }
        self.init_frozen.store(true, Ordering::Release);
        None
    }

    fn store_init_result(&self, result: RequestInitResult) -> RequestInitResult {
        *self.init_state.lock().expect("lock poisoned") = Some(result.clone());
        self.init_frozen.store(true, Ordering::Release);
        result
    }

    fn store_first_init_error(&self, error: RequestError) {
        let mut guard = self.init_state.lock().expect("lock poisoned");
        if guard.is_none() && !self.init_frozen.load(Ordering::Acquire) {
            *guard = Some(Err(error));
            self.init_frozen.store(true, Ordering::Release);
        }
    }

    fn store_malformed_request(&self, error: MalformedRequestError) {
        self.store_first_init_error(RequestError::MalformedRequest {
            source: Arc::new(error),
        });
    }

    fn operate_request(
        &self,
        operation: &'static str,
        operate: impl FnOnce(&mut Message) -> Result<(), MalformedRequestError>,
    ) {
        let mut message = self.message();
        if message.is_malformed() {
            tracing::warn!(
                operation,
                "request is malformed, operation will not affect the request stream"
            );
            return;
        }
        if let Err(error) = operate(&mut message) {
            let report = Report::from_error(&error);
            tracing::warn!(
                operation,
                error = %report,
                "operation malformed the request message, request stream will be cancelled"
            );
            self.store_malformed_request(error);
            message.set_malformed();
        }
    }

    fn operate_message(
        &self,
        operation: &'static str,
        operate: impl FnOnce(&mut Message) -> Result<(), MalformedMessageError>,
    ) {
        self.operate_request(operation, |message| {
            operate(message).context(malformed_request_error::MessageOperationSnafu { operation })
        });
    }

    fn local_dhttp_name(&self) -> Option<dhttp_identity::name::DhttpName<'static>> {
        self.endpoint.quic().identity().map(|identity| {
            crate::endpoint::Endpoint::name_from_identity(&identity)
                .expect("BUG: dhttp endpoint identity must be a valid dhttp name")
        })
    }

    fn normalize_request_uri(&self, uri: impl IntoUri) -> Result<Uri, MalformedRequestError> {
        let base = self.local_dhttp_name();
        uri.into_uri(base.as_ref())
            .context(malformed_request_error::UriSnafu)
    }

    async fn ensure_stream_init(&self) -> Result<(), RequestError> {
        if let Some(cached) = self.init_result() {
            return cached;
        }

        let _init_guard = self.init_lock.lock().await;
        if let Some(cached) = self.init_result_or_start_init() {
            return cached;
        }

        let result: RequestInitResult = async {
            let authority = self
                .authority
                .lock()
                .expect("lock poisoned")
                .clone()
                .ok_or_else(|| RequestError::MalformedRequestHeader {
                    source: Arc::new(MalformedHeaderSection::EmptyAuthorityOrHost),
                })?;
            {
                let message = self.message();
                if let Err(error) = message.validate_header_for_send() {
                    return Err(match error {
                        MalformedMessageError::MalformedPseudoHeader { source } => {
                            RequestError::MalformedRequestHeader {
                                source: Arc::new(source),
                            }
                        }
                        source => RequestError::MalformedRequest {
                            source: Arc::new(MalformedRequestError::MessageOperation {
                                operation: "validate_header_for_send",
                                source,
                            }),
                        },
                    });
                }
            }
            let connection = self.endpoint.connect(authority).await?;
            let (read_stream, write_stream) = connection
                .initial_message_stream()
                .await
                .context(StreamInitSnafu)?;
            *self.read_stream.lock().await = Some(read_stream);
            *self.write_stream.lock().await = Some(write_stream);
            Ok(())
        }
        .await;

        self.store_init_result(result)
    }

    async fn take_read_stream(&self) -> Result<ReadStream, RequestError> {
        self.ensure_stream_init().await?;
        self.read_stream
            .lock()
            .await
            .take()
            .ok_or(RequestError::Acquire {
                source: AcquireError::AlreadyTaken,
            })
    }

    async fn initialized_write_stream(
        &self,
    ) -> Result<tokio::sync::MappedMutexGuard<'_, WriteStream>, RequestError> {
        let write_guard = self.write_stream.lock().await;
        if write_guard.is_none() {
            return Err(RequestError::Acquire {
                source: AcquireError::AlreadyTaken,
            });
        }
        Ok(tokio::sync::MutexGuard::map(write_guard, |stream| {
            stream
                .as_mut()
                .expect("write stream is present after explicit check")
        }))
    }

    async fn acquire_write_stream(
        &self,
    ) -> Result<tokio::sync::MappedMutexGuard<'_, WriteStream>, RequestError> {
        self.ensure_stream_init().await?;
        self.initialized_write_stream().await
    }

    async fn write_stream(
        &self,
    ) -> Result<tokio::sync::MappedMutexGuard<'_, WriteStream>, RequestError> {
        self.send_buffered_request().await?;
        self.initialized_write_stream().await
    }

    async fn read_response(&self) -> Result<Response, RequestError> {
        let mut stream = self.take_read_stream().await?;
        let mut message = Message::unresolved_response();
        message.read_header_from(&mut stream).await?;

        let agent = stream.connection().remote_agent().await?.expect(
            "remote agent should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message,
            agent,
            stream,
        })
    }

    async fn send_request_to_goal(&self, goal: MessageWriteGoal) -> Result<(), RequestError> {
        let mut write_stream = self.acquire_write_stream().await?;

        loop {
            let flow = {
                let mut message = self.message();
                message.write_next_part_to(&mut write_stream, goal)
            }
            .await;

            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(result) => {
                    if result.is_err() {
                        self.mark_message_failed_unless_malformed();
                    }
                    result?;
                    return Ok(());
                }
            }
        }
    }

    async fn send_request_header(&self) -> Result<(), RequestError> {
        self.send_request_to_goal(MessageWriteGoal::Header).await
    }

    async fn write_body_chunk(&self, content: Body) -> Result<(), RequestError> {
        let mut write_stream = self.acquire_write_stream().await?;

        let result = {
            let mut message = self.message();
            message.write_streaming_body_to(&mut write_stream, content)
        }
        .await;
        if result.is_err() {
            self.mark_message_failed_unless_malformed();
        }
        result?;
        Ok(())
    }

    async fn flush_request(&self) -> Result<(), RequestError> {
        self.write_stream().await?.flush().await?;
        Ok(())
    }

    async fn close_request(&self) -> Result<(), RequestError> {
        self.write_stream().await?.close().await?;
        Ok(())
    }

    async fn cancel_request(&self, code: Code) -> Result<(), RequestError> {
        self.acquire_write_stream().await?.cancel(code).await?;
        Ok(())
    }

    async fn send_buffered_request(&self) -> Result<(), RequestError> {
        self.send_request_to_goal(MessageWriteGoal::Complete).await
    }

    async fn into_response(self) -> Result<Response, RequestError> {
        self.close_request().await?;
        let mut read_stream = self.take_read_stream().await?;
        let mut response_message = Message::unresolved_response();
        response_message.read_header_from(&mut read_stream).await?;

        let agent = read_stream.connection().remote_agent().await?.expect(
            "remote agent should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message: response_message,
            agent,
            stream: read_stream,
        })
    }
}

pub struct Request {
    state: Arc<RequestState>,
}

impl Request {
    pub(crate) fn new(state: Arc<RequestState>) -> Self {
        Self { state }
    }
}

impl Clone for Request {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl Request {
    pub fn set_method(&self, method: Method) -> &Self {
        self.state.operate_message("set_method", |message| {
            message.header_mut()?.set_method(method);
            Ok(())
        });
        self
    }

    pub fn set_uri(&self, uri: impl IntoUri) -> &Self {
        self.state.operate_request("set_uri", |message| {
            message
                .header_mut()
                .context(malformed_request_error::MessageOperationSnafu {
                    operation: "set_uri",
                })?;
            let uri = self.state.normalize_request_uri(uri)?;
            if let Some(auth) = uri.authority().cloned() {
                self.state
                    .set_authority(auth)
                    .context(malformed_request_error::AuthorityFrozenSnafu)?;
            }
            message
                .header_mut()
                .context(malformed_request_error::MessageOperationSnafu {
                    operation: "set_uri",
                })?
                .set_uri(uri);
            Ok(())
        });
        self
    }

    pub fn set_header(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        self.state.operate_message("set_header", |message| {
            message.header_mut()?.header_map_mut().insert(name, value);
            Ok(())
        });
        self
    }

    pub fn set_headers(&self, headers: HeaderMap) -> &Self {
        self.state.operate_message("set_headers", |message| {
            message.header_mut()?.header_map_mut().extend(headers);
            Ok(())
        });
        self
    }

    pub fn set_body(&self, content: impl IntoBody) -> &Self {
        self.state.operate_message("set_body", |message| {
            message.set_body(content)?;
            Ok(())
        });
        self
    }

    pub fn set_trailer(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        self.state.operate_message("set_trailer", |message| {
            message.trailers_mut()?.insert(name, value);
            Ok(())
        });
        self
    }

    pub fn set_trailers(&self, trailers: HeaderMap) -> &Self {
        self.state.operate_message("set_trailers", |message| {
            message.trailers_mut()?.extend(trailers);
            Ok(())
        });
        self
    }

    pub fn method(self, method: Method) -> Self {
        self.set_method(method);
        self
    }

    pub fn uri(self, uri: impl IntoUri) -> Self {
        self.set_uri(uri);
        self
    }

    pub fn header(self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.set_header(name, value);
        self
    }

    pub fn headers(self, headers: HeaderMap) -> Self {
        self.set_headers(headers);
        self
    }

    pub fn body(self, content: impl IntoBody) -> Self {
        self.set_body(content);
        self
    }

    pub fn trailer(self, name: impl IntoHeaderName, value: HeaderValue) -> Self {
        self.set_trailer(name, value);
        self
    }

    pub fn trailers(self, trailers: HeaderMap) -> Self {
        self.set_trailers(trailers);
        self
    }

    pub fn write<B>(
        &self,
        content: B,
    ) -> impl Future<Output = Result<&Self, RequestError>> + use<'_, B>
    where
        B: IntoBody,
    {
        let content = content.into_body();
        async move {
            self.state.write_body_chunk(content).await?;
            Ok(self)
        }
    }

    pub async fn flush(&self) -> Result<&Self, RequestError> {
        self.state.flush_request().await?;
        Ok(self)
    }

    pub async fn close(&self) -> Result<(), RequestError> {
        self.state.close_request().await
    }

    pub async fn cancel(&self, code: Code) -> Result<(), RequestError> {
        self.state.cancel_request(code).await
    }

    /// Sends the request header and waits for the response.
    ///
    /// This method intentionally sends only the header section. It is meant for
    /// full-duplex requests where another owner of the same request may continue
    /// writing the body. If the whole buffered request should be sent before waiting
    /// for the response, use [`Self::into_response`] when the request is uniquely
    /// owned.
    pub async fn response(&self) -> Result<Response, RequestError> {
        self.state.send_request_header().await?;
        self.state.read_response().await
    }

    /// Sends the whole buffered request when uniquely owned, then waits for the response.
    ///
    /// If other `Request` clones still exist, this falls back to [`Self::response`]
    /// and therefore only sends the request header before waiting for the response.
    pub async fn into_response(self) -> Result<Response, RequestError> {
        match Arc::try_unwrap(self.state) {
            Ok(state) => state.into_response().await,
            Err(state) => {
                let request = Request { state };
                request.response().await
            }
        }
    }
}

impl IntoFuture for Request {
    type Output = Result<Response, RequestError>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.into_response())
    }
}

pub struct Response {
    message: Message,
    stream: ReadStream,
    agent: Arc<dyn agent::RemoteAgent>,
}

impl Response {
    pub async fn next_response(&mut self) -> Result<&mut Self, MessageStreamError> {
        self.message.read_header_from(&mut self.stream).await?;
        Ok(self)
    }

    pub fn status(&self) -> http::StatusCode {
        self.message.header().status()
    }

    pub fn headers(&mut self) -> &HeaderMap {
        self.message.header().header_map()
    }

    pub fn header(&mut self, name: impl AsHeaderName) -> Option<&HeaderValue> {
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

    pub fn agent(&self) -> &Arc<dyn agent::RemoteAgent> {
        &self.agent
    }
}
