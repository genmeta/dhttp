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
//!
//! ```compile_fail
//! fn response_identity_uses_authority(response: &dhttp::endpoint::client::Response) {
//!     let _ = response.remote_authority();
//! }
//! ```

use std::{
    future::{Future, IntoFuture},
    mem,
    ops::ControlFlow,
    sync::{Arc, Mutex as SyncMutex},
};

use bytes::{Buf, Bytes};
use dhttp_identity::identity as authority;
use futures::{Stream, StreamExt, future::BoxFuture};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{PathAndQuery, Scheme},
};
use snafu::{Report, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    endpoint::client::request_error::StreamInitSnafu,
    h3x::{
        buflist::BuflistCursor,
        dhttp::message::{
            InitialMessageStreamError, MessageReader, MessageStreamError, MessageWriter,
        },
        error::Code,
        pool::ConnectError,
        qpack::field::{FieldSection, MalformedHeaderSection, PseudoHeaders},
        quic,
    },
    message::{
        Body, BodyState, IntoBody, IntoUri, IntoUriError, MessageOperationError, MessageStage,
        MessageWriteFlow, MessageWriteGoal, MutateTrailersError, PrepareStreamingBodyWriteError,
        PreparedMessageWrite, PreparedStreamingBody, ReadBufferedBodyError, ReadStreamingBodyError,
        ReadToStringError, ReadTrailersError, RequestHeader, RequestMessage, ResponseMessage,
        SetBodyError, Trailer, WriteStreamingBodyError, execute_prepared_message_write,
        execute_prepared_streaming_body_write, write_streaming_body_error,
    },
};

type DquicH3Endpoint = crate::h3x::dquic::H3Endpoint;
type DquicConnectError = crate::dquic::ConnectError;
type RequestInitResult = Result<(), RequestError>;

fn context_request_build<T>(result: Result<T, RequestBuildError>) -> Result<T, RequestError> {
    // SNAFU context selectors require the source type to match exactly.
    // `RequestError` stores build errors behind `Arc` so cached init results can
    // be cloned, so this structural wrapping happens before the selector builds
    // the public error.
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(Arc::new(error)).context(request_error::BuildSnafu),
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestBuildError {
    #[snafu(display("failed to convert request uri"))]
    Uri { source: IntoUriError },
    #[snafu(display("request header section is malformed"))]
    MalformedHeader { source: MalformedHeaderSection },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestMutationError {
    #[snafu(display("cannot modify request header after activation"))]
    HeaderAlreadyActivated,
    #[snafu(display("request message is unavailable after activation failed"))]
    MessageUnavailable,
    #[snafu(display("request message operation `{operation}` failed"))]
    MessageOperation {
        operation: &'static str,
        source: MessageOperationError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestError {
    #[snafu(display("request cannot be sent because it was not built"))]
    Build { source: Arc<RequestBuildError> },
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
    #[snafu(display("failed to write request body"))]
    WriteStreamingBody { source: WriteStreamingBodyError },
    #[snafu(transparent)]
    MessageStream { source: MessageStreamError },
}

impl From<ConnectError<DquicConnectError>> for RequestError {
    fn from(source: ConnectError<DquicConnectError>) -> Self {
        Err::<(), _>(Arc::new(source))
            .context(request_error::ConnectSnafu)
            .expect_err("request connect conversion must produce an error")
    }
}
impl Clone for RequestError {
    fn clone(&self) -> Self {
        match self {
            Self::Build { source } => Self::Build {
                source: Arc::clone(source),
            },
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
            Self::WriteStreamingBody { source } => Self::WriteStreamingBody {
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

#[derive(Debug)]
enum PendingUri {
    Missing,
    Parsed(Uri),
    Invalid(IntoUriError),
}

#[derive(Debug)]
struct PendingRequest {
    method: Option<Method>,
    uri: PendingUri,
    headers: HeaderMap,
    body: BodyState,
    trailer: HeaderMap,
}

impl Default for PendingRequest {
    fn default() -> Self {
        Self {
            method: None,
            uri: PendingUri::Missing,
            headers: HeaderMap::new(),
            body: BodyState::Pending,
            trailer: HeaderMap::new(),
        }
    }
}

impl PendingRequest {
    fn into_message(self) -> Result<RequestMessage, RequestBuildError> {
        let pseudo = match self.uri {
            PendingUri::Missing => PseudoHeaders::Request {
                method: self.method,
                scheme: None,
                authority: None,
                path: None,
                protocol: None,
            },
            PendingUri::Parsed(uri) => {
                let uri = uri.into_parts();
                let path = match uri.path_and_query {
                    Some(path) => Some(path),
                    None if uri.scheme == Some(Scheme::HTTP)
                        || uri.scheme == Some(Scheme::HTTPS) =>
                    {
                        Some(PathAndQuery::from_static("/"))
                    }
                    None if self.method == Some(Method::OPTIONS) => {
                        Some(PathAndQuery::from_static("/"))
                    }
                    None => None,
                };
                PseudoHeaders::Request {
                    method: self.method,
                    scheme: uri.scheme,
                    authority: uri.authority,
                    path,
                    protocol: None,
                }
            }
            PendingUri::Invalid(source) => return Err(RequestBuildError::Uri { source }),
        };
        let header = RequestHeader::try_from(FieldSection::header(pseudo, self.headers))
            .context(request_build_error::MalformedHeaderSnafu)?;
        Ok(RequestMessage::with_parts(
            header,
            self.body,
            Trailer::new(self.trailer),
        ))
    }
}

#[derive(Debug)]
enum RequestMessageState {
    Pending(PendingRequest),
    Active(ActiveRequestMessage),
    Failed,
}

impl Default for RequestMessageState {
    fn default() -> Self {
        Self::Pending(PendingRequest::default())
    }
}

#[derive(Debug)]
struct ActiveRequestMessage {
    message: RequestMessage,
    in_flight_stage: Option<MessageStage>,
}

impl ActiveRequestMessage {
    fn new(message: RequestMessage) -> Self {
        Self {
            message,
            in_flight_stage: None,
        }
    }

    fn effective_stage(&self) -> MessageStage {
        self.in_flight_stage
            .unwrap_or(self.message.stage())
            .max(self.message.stage())
    }

    fn prepare_message_write(&mut self, goal: MessageWriteGoal) -> PreparedMessageWrite {
        let prepared = self.message.prepare_message_write(goal);
        self.in_flight_stage = prepared.in_flight_stage();
        prepared
    }

    fn prepare_streaming_body_write(
        &mut self,
        content: Body,
    ) -> Result<PreparedStreamingBody, PrepareStreamingBodyWriteError> {
        let prepared = self.message.prepare_streaming_body_write(content)?;
        self.in_flight_stage = prepared.in_flight_stage();
        Ok(prepared)
    }

    fn clear_in_flight(&mut self) {
        self.in_flight_stage = None;
    }

    fn set_body(&mut self, content: Body) -> Result<(), MessageOperationError> {
        if self.effective_stage() > MessageStage::Header {
            return Err(SetBodyError::BodyReplacementDuringSend.into());
        }
        self.message.set_body(content)?;
        Ok(())
    }

    fn trailers_mut(&mut self) -> Result<&mut HeaderMap, MessageOperationError> {
        if self.effective_stage() > MessageStage::Trailer {
            return Err(MutateTrailersError::AlreadySent.into());
        }
        Ok(self.message.trailers_mut()?)
    }
}

pub(crate) struct RequestState {
    message: SyncMutex<RequestMessageState>,
    write_stream: AsyncMutex<Option<MessageWriter>>,
    read_stream: AsyncMutex<Option<MessageReader>>,
    // Shared result slot for both synchronous request construction failures and
    // asynchronous stream initialization. Synchronous setters cannot await, so
    // `init_lock` only serializes the async initialization path.
    init_state: SyncMutex<Option<RequestInitResult>>,
    init_lock: AsyncMutex<()>,
    endpoint: Arc<DquicH3Endpoint>,
}

impl RequestState {
    pub(crate) fn new(endpoint: Arc<DquicH3Endpoint>) -> Self {
        Self {
            message: SyncMutex::new(RequestMessageState::default()),
            write_stream: AsyncMutex::new(None),
            read_stream: AsyncMutex::new(None),
            init_state: SyncMutex::new(None),
            init_lock: AsyncMutex::new(()),
            endpoint,
        }
    }

    fn message(&self) -> std::sync::MutexGuard<'_, RequestMessageState> {
        self.message.lock().expect("lock poisoned")
    }

    fn init_result(&self) -> Option<RequestInitResult> {
        self.init_state.lock().expect("lock poisoned").clone()
    }

    fn init_result_or_start_init(&self) -> Option<RequestInitResult> {
        let guard = self.init_state.lock().expect("lock poisoned");
        if let Some(result) = guard.as_ref() {
            return Some(result.clone());
        }
        None
    }

    fn store_init_result(&self, result: RequestInitResult) -> RequestInitResult {
        *self.init_state.lock().expect("lock poisoned") = Some(result.clone());
        result
    }

    fn store_send_error(&self, source: MessageStreamError) -> RequestError {
        let mut state = self.message();
        *state = RequestMessageState::Failed;
        drop(state);
        let error = RequestError::MessageStream { source };
        *self.init_state.lock().expect("lock poisoned") = Some(Err(error.clone()));
        error
    }

    fn store_write_streaming_body_error(&self, source: WriteStreamingBodyError) -> RequestError {
        let mut state = self.message();
        *state = RequestMessageState::Failed;
        drop(state);
        let error = Err::<(), _>(source)
            .context(request_error::WriteStreamingBodySnafu)
            .expect_err("request write streaming body conversion must produce an error");
        *self.init_state.lock().expect("lock poisoned") = Some(Err(error.clone()));
        error
    }

    fn reject_mutation(&self, operation: &'static str, error: RequestMutationError) {
        let report = Report::from_error(&error);
        tracing::warn!(
            operation,
            error = %report,
            "request mutation was rejected, operation will not affect the request stream"
        );
    }

    fn local_dhttp_name(&self) -> Option<dhttp_identity::name::DhttpName<'static>> {
        self.endpoint.quic().identity().map(|identity| {
            crate::endpoint::Endpoint::name_from_identity(&identity)
                .expect("BUG: dhttp endpoint identity must be a valid dhttp name")
        })
    }

    fn activate_message(&self) -> Result<http::uri::Authority, RequestError> {
        let mut state = self.message();
        let current = mem::replace(&mut *state, RequestMessageState::Failed);
        match current {
            RequestMessageState::Pending(pending) => {
                let message = match context_request_build(pending.into_message()) {
                    Ok(message) => message,
                    Err(error) => {
                        *state = RequestMessageState::Failed;
                        return Err(error);
                    }
                };
                let authority = message.header().authority().clone();
                *state = RequestMessageState::Active(ActiveRequestMessage::new(message));
                Ok(authority)
            }
            RequestMessageState::Active(active) => {
                let authority = active.message.header().authority().clone();
                *state = RequestMessageState::Active(active);
                Ok(authority)
            }
            RequestMessageState::Failed => {
                *state = RequestMessageState::Failed;
                unreachable!("failed request activation must have cached init result")
            }
        }
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
            let authority = self.activate_message()?;
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

    async fn take_read_stream(&self) -> Result<MessageReader, RequestError> {
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
    ) -> Result<tokio::sync::MappedMutexGuard<'_, MessageWriter>, RequestError> {
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
    ) -> Result<tokio::sync::MappedMutexGuard<'_, MessageWriter>, RequestError> {
        self.ensure_stream_init().await?;
        self.initialized_write_stream().await
    }

    async fn write_stream(
        &self,
    ) -> Result<tokio::sync::MappedMutexGuard<'_, MessageWriter>, RequestError> {
        self.send_buffered_request().await?;
        self.initialized_write_stream().await
    }

    async fn read_response(&self) -> Result<Response, RequestError> {
        let mut stream = self.take_read_stream().await?;
        let message = ResponseMessage::read_from(&mut stream).await?;

        let remote_authority = stream.connection().remote_authority().await?.expect(
            "remote authority should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message,
            authority: remote_authority,
            stream,
        })
    }

    async fn send_request_to_goal(&self, goal: MessageWriteGoal) -> Result<(), RequestError> {
        enum PreparedRequestWrite {
            Pending(PreparedMessageWrite),
            Complete(MessageWriteFlow),
        }

        let mut write_stream = self.acquire_write_stream().await?;

        loop {
            let prepared = {
                let mut state = self.message();
                let RequestMessageState::Active(active) = &mut *state else {
                    unreachable!("active message exists after stream initialization")
                };
                let prepared = active.prepare_message_write(goal);
                match prepared.try_into_executed_without_io() {
                    Ok(executed) => {
                        let flow = active.message.commit_executed_message_write(executed);
                        active.clear_in_flight();
                        PreparedRequestWrite::Complete(flow)
                    }
                    Err(prepared) => PreparedRequestWrite::Pending(prepared),
                }
            };

            let prepared = match prepared {
                PreparedRequestWrite::Pending(prepared) => prepared,
                PreparedRequestWrite::Complete(flow) => match flow {
                    ControlFlow::Continue(()) => continue,
                    ControlFlow::Break(Ok(())) => return Ok(()),
                    ControlFlow::Break(Err(error)) => return Err(self.store_send_error(error)),
                },
            };

            let executed = match execute_prepared_message_write(&mut write_stream, prepared).await {
                Ok(executed) => executed,
                Err(error) => return Err(self.store_send_error(error)),
            };

            let flow = {
                let mut state = self.message();
                let RequestMessageState::Active(active) = &mut *state else {
                    unreachable!("active message exists after successful request write")
                };
                let flow = active.message.commit_executed_message_write(executed);
                active.clear_in_flight();
                flow
            };

            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(Ok(())) => return Ok(()),
                ControlFlow::Break(Err(error)) => return Err(self.store_send_error(error)),
            }
        }
    }

    async fn send_request_header(&self) -> Result<(), RequestError> {
        self.send_request_to_goal(MessageWriteGoal::Header).await
    }

    async fn write_body_chunk(&self, content: Body) -> Result<(), RequestError> {
        enum BodyWritePreparation {
            Send(PreparedStreamingBody),
            Malformed(PrepareStreamingBodyWriteError),
        }

        let mut write_stream = self.acquire_write_stream().await?;

        let prepared = {
            let mut state = self.message();
            let RequestMessageState::Active(active) = &mut *state else {
                unreachable!("active message exists after stream initialization")
            };
            match active.prepare_streaming_body_write(content) {
                Ok(prepared) => BodyWritePreparation::Send(prepared),
                Err(error) => BodyWritePreparation::Malformed(error),
            }
        };
        let prepared = match prepared {
            BodyWritePreparation::Send(prepared) => prepared,
            BodyWritePreparation::Malformed(error) => {
                _ = write_stream.reset(Code::H3_MESSAGE_ERROR).await;
                let error = Err::<(), _>(error)
                    .context(write_streaming_body_error::PrepareSnafu)
                    .expect_err("write streaming body prepare error conversion must fail");
                return Err(self.store_write_streaming_body_error(error));
            }
        };

        let commit = match execute_prepared_streaming_body_write(&mut write_stream, prepared).await
        {
            Ok(commit) => commit,
            Err(error) => {
                let error = Err::<(), _>(error)
                    .context(write_streaming_body_error::StreamSnafu)
                    .expect_err("write streaming body stream error conversion must fail");
                return Err(self.store_write_streaming_body_error(error));
            }
        };

        let result = {
            let mut state = self.message();
            let RequestMessageState::Active(active) = &mut *state else {
                unreachable!("active message exists after stream initialization")
            };
            let result = active.message.commit_streaming_body_write(commit);
            if result.is_ok() {
                active.clear_in_flight();
            }
            result
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                _ = write_stream.reset(Code::H3_MESSAGE_ERROR).await;
                let error = Err::<(), _>(error)
                    .context(write_streaming_body_error::CommitSnafu)
                    .expect_err("write streaming body commit error conversion must fail");
                Err(self.store_write_streaming_body_error(error))
            }
        }
    }

    async fn flush_request(&self) -> Result<(), RequestError> {
        self.write_stream().await?.flush().await?;
        Ok(())
    }

    async fn close_request(&self) -> Result<(), RequestError> {
        self.write_stream().await?.close().await?;
        Ok(())
    }

    async fn reset_request(&self, code: Code) -> Result<(), RequestError> {
        self.acquire_write_stream().await?.reset(code).await?;
        Ok(())
    }

    async fn send_buffered_request(&self) -> Result<(), RequestError> {
        self.send_request_to_goal(MessageWriteGoal::Complete).await
    }

    async fn into_response(self) -> Result<Response, RequestError> {
        self.close_request().await?;
        let mut read_stream = self.take_read_stream().await?;
        let response_message = ResponseMessage::read_from(&mut read_stream).await?;

        let remote_authority = read_stream.connection().remote_authority().await?.expect(
            "remote authority should be present(should be guaranteed by h3 connection establishment)",
        );
        Ok(Response {
            message: response_message,
            authority: remote_authority,
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
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => pending.method = Some(method),
            RequestMessageState::Active(_) => self
                .state
                .reject_mutation("set_method", RequestMutationError::HeaderAlreadyActivated),
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_method", RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_uri(&self, uri: impl IntoUri) -> &Self {
        let operation = "set_uri";
        let base = self.state.local_dhttp_name();
        let uri = match uri.into_uri(base.as_ref()) {
            Ok(uri) => PendingUri::Parsed(uri),
            Err(error) => PendingUri::Invalid(error),
        };
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => pending.uri = uri,
            RequestMessageState::Active(_) => self
                .state
                .reject_mutation(operation, RequestMutationError::HeaderAlreadyActivated),
            RequestMessageState::Failed => self
                .state
                .reject_mutation(operation, RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_header(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => {
                pending.headers.insert(name, value);
            }
            RequestMessageState::Active(_) => self
                .state
                .reject_mutation("set_header", RequestMutationError::HeaderAlreadyActivated),
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_header", RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_headers(&self, headers: HeaderMap) -> &Self {
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => pending.headers.extend(headers),
            RequestMessageState::Active(_) => self
                .state
                .reject_mutation("set_headers", RequestMutationError::HeaderAlreadyActivated),
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_headers", RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_body(&self, content: impl IntoBody) -> &Self {
        let content = content.into_body();
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => {
                pending.body = BodyState::Buffered {
                    buflist: BuflistCursor::new(content),
                };
            }
            RequestMessageState::Active(active) => {
                if let Err(error) = (|| {
                    active.set_body(content)?;
                    Ok(())
                })()
                .context(request_mutation_error::MessageOperationSnafu {
                    operation: "set_body",
                }) {
                    self.state.reject_mutation("set_body", error);
                }
            }
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_body", RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_trailer(&self, name: impl IntoHeaderName, value: HeaderValue) -> &Self {
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => {
                pending.trailer.insert(name, value);
            }
            RequestMessageState::Active(active) => {
                if let Err(error) = (|| {
                    active.trailers_mut()?.insert(name, value);
                    Ok(())
                })()
                .context(request_mutation_error::MessageOperationSnafu {
                    operation: "set_trailer",
                }) {
                    self.state.reject_mutation("set_trailer", error);
                }
            }
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_trailer", RequestMutationError::MessageUnavailable),
        }
        self
    }

    pub fn set_trailers(&self, trailers: HeaderMap) -> &Self {
        let mut state = self.state.message();
        match &mut *state {
            RequestMessageState::Pending(pending) => pending.trailer.extend(trailers),
            RequestMessageState::Active(active) => {
                if let Err(error) = (|| {
                    active.trailers_mut()?.extend(trailers);
                    Ok(())
                })()
                .context(request_mutation_error::MessageOperationSnafu {
                    operation: "set_trailers",
                }) {
                    self.state.reject_mutation("set_trailers", error);
                }
            }
            RequestMessageState::Failed => self
                .state
                .reject_mutation("set_trailers", RequestMutationError::MessageUnavailable),
        }
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

    pub async fn reset(&self, code: Code) -> Result<(), RequestError> {
        self.state.reset_request(code).await
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
    message: ResponseMessage,
    stream: MessageReader,
    authority: Arc<dyn authority::RemoteAuthority>,
}

impl Response {
    pub async fn next_response(&mut self) -> Result<&mut Self, MessageStreamError> {
        self.message.read_header_from(&mut self.stream).await?;
        Ok(self)
    }

    pub fn status(&self) -> http::StatusCode {
        self.message.header().status()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.message.header().header_map()
    }

    pub fn header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, ReadStreamingBodyError>> {
        self.message
            .read_streaming_body_from(&mut self.stream)
            .await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, ReadBufferedBodyError> {
        self.message.read_buffered_body_from(&mut self.stream).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, ReadBufferedBodyError> {
        self.message.collect_bytes_body_from(&mut self.stream).await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.message
            .collect_string_body_from(&mut self.stream)
            .await
    }

    pub async fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, ReadStreamingBodyError>> {
        futures::stream::unfold(self, async |this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn into_stream(self) -> impl Stream<Item = Result<Bytes, ReadStreamingBodyError>> {
        futures::stream::unfold(self, async |mut this| {
            this.read().await.map(|item| (item, this))
        })
        .fuse()
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, ReadTrailersError> {
        self.message.read_trailers_from(&mut self.stream).await
    }

    pub async fn stop(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.stream.stop(code).await
    }

    pub fn authority(&self) -> &Arc<dyn authority::RemoteAuthority> {
        &self.authority
    }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use crate::{
        h3x::qpack::field::{FieldSection, PseudoHeaders},
        message::{MessageOperationError, MutateTrailersError, SetBodyError},
    };

    use super::*;

    #[test]
    fn response_authority_accessor_has_directional_identity_name() {
        let _response_authority = |response: &Response| {
            let _: &Arc<dyn authority::RemoteAuthority> = response.authority();
        };
    }

    fn request_message() -> RequestMessage {
        let section = FieldSection::header(
            PseudoHeaders::request(Method::GET, "https://example.com/".parse().unwrap()),
            HeaderMap::new(),
        );
        let header = RequestHeader::try_from(section).unwrap();
        RequestMessage::new(header)
    }

    #[test]
    fn request_in_flight_stage_rejects_body_mutation_before_stage_commit() {
        let mut active = ActiveRequestMessage::new(request_message());

        let _prepared = active.prepare_message_write(MessageWriteGoal::Header);

        assert_eq!(active.message.stage(), MessageStage::Header);
        assert_eq!(active.effective_stage(), MessageStage::Body);
        let error = active.set_body("late".into_body()).unwrap_err();
        assert!(matches!(
            error,
            MessageOperationError::SetBody {
                source: SetBodyError::BodyReplacementDuringSend
            }
        ));
    }

    #[test]
    fn request_in_flight_complete_stage_rejects_trailer_mutation() {
        let mut active = ActiveRequestMessage::new(request_message());
        active.in_flight_stage = Some(MessageStage::Complete);

        let error = active.trailers_mut().unwrap_err();

        assert!(matches!(
            error,
            MessageOperationError::MutateTrailers {
                source: MutateTrailersError::AlreadySent
            }
        ));
    }
}
