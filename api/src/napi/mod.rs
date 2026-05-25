use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};

use ::napi::{
    Error, Status,
    bindgen_prelude::{
        Buffer, Either, FnArgs, Function, Promise, Result as NapiResult,
        within_runtime_if_available,
    },
};
use napi_derive::napi;

fn napi_error(error: crate::error::DhttpError) -> Error {
    Error::new(Status::GenericFailure, error.report().to_owned())
}

fn dhttp_napi_error(operation: &'static str, error: Error) -> crate::error::DhttpError {
    crate::error::DhttpError::from_error(operation, error)
}

fn state_error(operation: &'static str, message: &'static str) -> Error {
    napi_error(crate::error::DhttpError::from_message(operation, message))
}

static DROP_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to create dhttp napi drop runtime")
});

fn drop_with_napi_runtime<T>(value: T) {
    let _guard = DROP_RUNTIME.enter();
    drop(value);
}

type StreamHandlerArgs = FnArgs<(IncomingStream,)>;
type StreamHandlerResult = Either<Promise<()>, ()>;

#[allow(dead_code)]
fn keep_rust_wrapper_shared_handles_reachable(
    request: &crate::endpoint::client::Request,
    server_request: &crate::endpoint::server::Request,
    server_response: &crate::endpoint::server::Response,
) {
    let _ = request.shared_handle();
    let _ = server_request.shared_handle();
    let _ = server_response.shared_handle();
}

#[napi(object)]
pub struct HeaderField {
    pub name: Buffer,
    pub value: Buffer,
}

impl HeaderField {
    fn into_pair(self) -> (Vec<u8>, Vec<u8>) {
        (self.name.to_vec(), self.value.to_vec())
    }

    fn from_pair((name, value): (Vec<u8>, Vec<u8>)) -> Self {
        Self {
            name: Buffer::from(name),
            value: Buffer::from(value),
        }
    }
}

#[napi(js_name = "StreamPair")]
pub struct StreamPair {
    read_stream: Mutex<Option<ReadStream>>,
    write_stream: Mutex<Option<WriteStream>>,
}

impl StreamPair {
    fn new(
        read_stream: crate::stream::ReadStream,
        write_stream: crate::stream::WriteStream,
    ) -> Self {
        Self {
            read_stream: Mutex::new(Some(ReadStream::from(read_stream))),
            write_stream: Mutex::new(Some(WriteStream::from(write_stream))),
        }
    }

    fn take_read_stream(&self) -> NapiResult<ReadStream> {
        self.read_stream
            .lock()
            .map_err(|_| state_error("stream_pair.read_stream", "stream pair mutex is poisoned"))?
            .take()
            .ok_or_else(|| state_error("stream_pair.read_stream", "read stream is closed"))
    }

    fn take_write_stream(&self) -> NapiResult<WriteStream> {
        self.write_stream
            .lock()
            .map_err(|_| state_error("stream_pair.write_stream", "stream pair mutex is poisoned"))?
            .take()
            .ok_or_else(|| state_error("stream_pair.write_stream", "write stream is closed"))
    }
}

#[napi]
impl StreamPair {
    #[napi(getter)]
    pub fn read_stream(&self) -> NapiResult<ReadStream> {
        self.take_read_stream()
    }

    #[napi(getter)]
    pub fn write_stream(&self) -> NapiResult<WriteStream> {
        self.take_write_stream()
    }
}

#[napi(js_name = "IncomingStream")]
pub struct IncomingStream {
    stream_id: i64,
    read_stream: Mutex<Option<ReadStream>>,
    write_stream: Mutex<Option<WriteStream>>,
}

impl IncomingStream {
    fn from_core(incoming: crate::endpoint::incoming::IncomingStream) -> NapiResult<Self> {
        let stream_id = i64::try_from(incoming.stream_id()).map_err(|error| {
            napi_error(crate::error::DhttpError::from_error(
                "incoming_stream.stream_id",
                error,
            ))
        })?;
        let (read_stream, write_stream) = incoming.into_parts();
        Ok(Self {
            stream_id,
            read_stream: Mutex::new(Some(ReadStream::from(read_stream))),
            write_stream: Mutex::new(Some(WriteStream::from(write_stream))),
        })
    }

    fn take_read_stream(&self) -> NapiResult<ReadStream> {
        self.read_stream
            .lock()
            .map_err(|_| {
                state_error(
                    "incoming_stream.read_stream",
                    "incoming stream mutex is poisoned",
                )
            })?
            .take()
            .ok_or_else(|| state_error("incoming_stream.read_stream", "read stream is closed"))
    }

    fn take_write_stream(&self) -> NapiResult<WriteStream> {
        self.write_stream
            .lock()
            .map_err(|_| {
                state_error(
                    "incoming_stream.write_stream",
                    "incoming stream mutex is poisoned",
                )
            })?
            .take()
            .ok_or_else(|| state_error("incoming_stream.write_stream", "write stream is closed"))
    }
}

#[napi]
impl IncomingStream {
    #[napi(getter)]
    pub fn stream_id(&self) -> i64 {
        self.stream_id
    }

    #[napi(getter)]
    pub fn read_stream(&self) -> NapiResult<ReadStream> {
        self.take_read_stream()
    }

    #[napi(getter)]
    pub fn write_stream(&self) -> NapiResult<WriteStream> {
        self.take_write_stream()
    }
}

#[napi(js_name = "Identity")]
pub struct Identity {
    inner: crate::identity::Identity,
}

impl From<crate::identity::Identity> for Identity {
    fn from(inner: crate::identity::Identity) -> Self {
        Self { inner }
    }
}

#[napi]
impl Identity {
    #[napi]
    pub fn name(&self) -> String {
        self.inner.name()
    }

    #[napi]
    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner.cert_chain_der()
    }

    #[napi]
    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key_der()
    }
}

#[napi(js_name = "Config")]
pub struct Config {
    inner: crate::config::Config,
}

#[napi]
impl Config {
    #[napi(constructor)]
    pub fn new(path: String) -> Self {
        Self {
            inner: crate::config::Config::from_path(path),
        }
    }

    #[napi]
    pub fn load() -> NapiResult<Config> {
        crate::config::Config::load()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi]
    pub fn identity_config(&self, name: String) -> NapiResult<IdentityConfig> {
        self.inner
            .identity_config(&name)
            .map(|inner| IdentityConfig { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load_identity(&self, name: String) -> NapiResult<IdentityConfig> {
        self.inner
            .load_identity(&name)
            .await
            .map(|inner| IdentityConfig { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn identity_exists(&self, name: String) -> NapiResult<bool> {
        self.inner.identity_exists(&name).await.map_err(napi_error)
    }

    #[napi]
    pub async fn identities(&self) -> NapiResult<Vec<String>> {
        self.inner.identities().await.map_err(napi_error)
    }
}

#[napi(js_name = "IdentityConfig")]
pub struct IdentityConfig {
    inner: crate::config::IdentityConfig,
}

#[napi]
impl IdentityConfig {
    #[napi]
    pub fn from_path(path: String) -> NapiResult<IdentityConfig> {
        crate::config::IdentityConfig::from_path(path)
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn name(&self) -> String {
        self.inner.name()
    }

    #[napi]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi]
    pub async fn identity(&self) -> NapiResult<Identity> {
        self.inner
            .identity()
            .await
            .map(Identity::from)
            .map_err(napi_error)
    }
}

#[napi(js_name = "EndpointOptions")]
pub struct EndpointOptions {
    inner: crate::endpoint::EndpointOptions,
}

#[napi]
impl EndpointOptions {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: crate::endpoint::EndpointOptions::new(),
        }
    }

    #[napi]
    pub fn identity(&self) -> Option<Identity> {
        self.inner.identity().map(Identity::from)
    }

    #[napi]
    pub fn set_identity(&mut self, identity: &Identity) {
        self.inner.set_identity(identity.inner.clone());
    }

    #[napi]
    pub fn clear_identity(&mut self) {
        self.inner.clear_identity();
    }

    #[napi]
    pub fn add_dns_scheme(&mut self, scheme: String) -> NapiResult<()> {
        self.inner.add_dns_scheme(&scheme).map_err(napi_error)
    }

    #[napi]
    pub fn dns_schemes(&self) -> Vec<String> {
        self.inner.dns_schemes()
    }

    #[napi]
    pub fn clear_dns_schemes(&mut self) {
        self.inner.clear_dns_schemes();
    }

    #[napi]
    pub fn add_bind_pattern(&mut self, pattern: String) -> NapiResult<()> {
        self.inner.add_bind_pattern(&pattern).map_err(napi_error)
    }

    #[napi]
    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner.bind_patterns()
    }

    #[napi]
    pub fn clear_bind_patterns(&mut self) {
        self.inner.clear_bind_patterns();
    }
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[napi(js_name = "ReadStream")]
pub struct ReadStream {
    inner: Mutex<Option<crate::stream::ReadStream>>,
    closed: AtomicBool,
}

impl From<crate::stream::ReadStream> for ReadStream {
    fn from(inner: crate::stream::ReadStream) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            closed: AtomicBool::new(false),
        }
    }
}

impl Drop for ReadStream {
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(inner) => inner.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(inner) = inner {
            drop_with_napi_runtime(inner);
        }
    }
}

impl ReadStream {
    fn take_inner(&self, operation: &'static str) -> NapiResult<crate::stream::ReadStream> {
        let mut guard = self.inner.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => state_error(operation, "read stream is busy"),
            std::sync::TryLockError::Poisoned(_) => {
                state_error(operation, "read stream mutex is poisoned")
            }
        })?;
        guard.take().ok_or_else(|| {
            if self.closed.load(Ordering::SeqCst) {
                state_error(operation, "read stream is closed")
            } else {
                state_error(operation, "read stream is busy")
            }
        })
    }

    fn restore_inner(&self, inner: crate::stream::ReadStream) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(inner);
    }
}

#[napi]
impl ReadStream {
    #[napi]
    pub async fn read_data_frame_chunk(&self) -> NapiResult<Option<Vec<u8>>> {
        let operation = "read_stream.read_data_frame_chunk";
        let mut inner = self.take_inner(operation)?;
        let result = inner.read_data_frame_chunk().await;
        self.restore_inner(inner);
        result.map_err(napi_error)
    }

    #[napi]
    pub async fn read_header_frame(&self) -> NapiResult<Option<Vec<HeaderField>>> {
        let operation = "read_stream.read_header_frame";
        let mut inner = self.take_inner(operation)?;
        let result = inner.read_header_frame().await;
        self.restore_inner(inner);
        result
            .map(|headers| {
                headers.map(|headers| headers.into_iter().map(HeaderField::from_pair).collect())
            })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn stop(&self, code: u32) -> NapiResult<()> {
        let operation = "read_stream.stop";
        let mut inner = self.take_inner(operation)?;
        match inner.stop(u64::from(code)).await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.restore_inner(inner);
                Err(napi_error(error))
            }
        }
    }
}

#[napi(js_name = "WriteStream")]
pub struct WriteStream {
    inner: Mutex<Option<crate::stream::WriteStream>>,
    closed: AtomicBool,
}

impl From<crate::stream::WriteStream> for WriteStream {
    fn from(inner: crate::stream::WriteStream) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            closed: AtomicBool::new(false),
        }
    }
}

impl Drop for WriteStream {
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(inner) => inner.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(inner) = inner {
            drop_with_napi_runtime(inner);
        }
    }
}

impl WriteStream {
    fn take_inner(&self, operation: &'static str) -> NapiResult<crate::stream::WriteStream> {
        let mut guard = self.inner.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => state_error(operation, "write stream is busy"),
            std::sync::TryLockError::Poisoned(_) => {
                state_error(operation, "write stream mutex is poisoned")
            }
        })?;
        guard.take().ok_or_else(|| {
            if self.closed.load(Ordering::SeqCst) {
                state_error(operation, "write stream is closed")
            } else {
                state_error(operation, "write stream is busy")
            }
        })
    }

    fn restore_inner(&self, inner: crate::stream::WriteStream) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(inner);
    }
}

#[napi]
impl WriteStream {
    #[napi]
    pub async fn send_header(&self, headers: Vec<HeaderField>) -> NapiResult<()> {
        let operation = "write_stream.send_header";
        let headers = headers.into_iter().map(HeaderField::into_pair).collect();
        let mut inner = self.take_inner(operation)?;
        let result = inner.send_header(headers).await;
        self.restore_inner(inner);
        result.map_err(napi_error)
    }

    #[napi]
    pub async fn send_data(&self, data: Buffer) -> NapiResult<()> {
        let operation = "write_stream.send_data";
        let mut inner = self.take_inner(operation)?;
        let result = inner.send_data(data.to_vec()).await;
        self.restore_inner(inner);
        result.map_err(napi_error)
    }

    #[napi]
    pub async fn flush(&self) -> NapiResult<()> {
        let operation = "write_stream.flush";
        let mut inner = self.take_inner(operation)?;
        let result = inner.flush().await;
        self.restore_inner(inner);
        result.map_err(napi_error)
    }

    #[napi]
    pub async fn close(&self) -> NapiResult<()> {
        let operation = "write_stream.close";
        let mut inner = self.take_inner(operation)?;
        match inner.close().await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.restore_inner(inner);
                Err(napi_error(error))
            }
        }
    }

    #[napi]
    pub async fn cancel(&self, code: u32) -> NapiResult<()> {
        let operation = "write_stream.cancel";
        let mut inner = self.take_inner(operation)?;
        match inner.cancel(u64::from(code)).await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.restore_inner(inner);
                Err(napi_error(error))
            }
        }
    }
}

#[napi(js_name = "Connection")]
pub struct Connection {
    inner: crate::endpoint::connection::Connection,
}

impl From<crate::endpoint::connection::Connection> for Connection {
    fn from(inner: crate::endpoint::connection::Connection) -> Self {
        Self { inner }
    }
}

#[napi]
impl Connection {
    #[napi]
    pub async fn open_request_stream(&self) -> NapiResult<StreamPair> {
        self.inner
            .open_request_stream()
            .await
            .map(|(read_stream, write_stream)| StreamPair::new(read_stream, write_stream))
            .map_err(napi_error)
    }
}

#[napi(js_name = "ServeHandle")]
pub struct ServeHandle {
    inner: Option<crate::endpoint::ServeHandle>,
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop_with_napi_runtime(inner);
        }
    }
}

impl ServeHandle {
    fn inner(&self, operation: &'static str) -> NapiResult<&crate::endpoint::ServeHandle> {
        self.inner
            .as_ref()
            .ok_or_else(|| state_error(operation, "serve handle is closed"))
    }
}

#[napi]
impl ServeHandle {
    #[napi]
    pub async fn shutdown(&self) -> NapiResult<()> {
        self.inner("serve_handle.shutdown")?
            .shutdown()
            .await
            .map_err(napi_error)
    }

    #[napi]
    pub fn abort(&self) -> NapiResult<()> {
        self.inner("serve_handle.abort")?.abort();
        Ok(())
    }

    #[napi]
    pub fn is_finished(&self) -> NapiResult<bool> {
        Ok(self.inner("serve_handle.is_finished")?.is_finished())
    }

    #[napi]
    pub async fn closed(&self) -> NapiResult<()> {
        self.inner("serve_handle.closed")?
            .closed()
            .await
            .map_err(napi_error)
    }
}

#[napi(js_name = "Endpoint")]
pub struct Endpoint {
    inner: Option<crate::endpoint::Endpoint>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop_with_napi_runtime(inner);
        }
    }
}

impl Endpoint {
    fn inner(&self, operation: &'static str) -> NapiResult<&crate::endpoint::Endpoint> {
        self.inner
            .as_ref()
            .ok_or_else(|| state_error(operation, "endpoint is closed"))
    }
}

#[napi]
impl Endpoint {
    #[napi]
    pub async fn create(options: Option<&EndpointOptions>) -> NapiResult<Endpoint> {
        let options = options.map(|options| options.inner.clone());
        crate::endpoint::Endpoint::create(options)
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load(name: String) -> NapiResult<Endpoint> {
        crate::endpoint::Endpoint::load(name)
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load_from(path: String) -> NapiResult<Endpoint> {
        crate::endpoint::Endpoint::load_from(path)
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(napi_error)
    }

    #[napi]
    pub fn identity(&self) -> Option<Identity> {
        self.inner
            .as_ref()
            .and_then(crate::endpoint::Endpoint::identity)
            .map(Identity::from)
    }

    #[napi]
    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner
            .as_ref()
            .map(crate::endpoint::Endpoint::bind_patterns)
            .unwrap_or_default()
    }

    #[napi]
    pub async fn connect(&self, authority: String) -> NapiResult<Connection> {
        let endpoint = self.inner("endpoint.connect")?.clone();
        endpoint
            .connect(&authority)
            .await
            .map(Connection::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn serve_streams(
        &self,
        handler: Function<StreamHandlerArgs, StreamHandlerResult>,
    ) -> NapiResult<ServeHandle> {
        let handler = handler
            .build_threadsafe_function::<StreamHandlerArgs>()
            .callee_handled::<false>()
            .build()?;
        let handler = Arc::new(handler);
        let endpoint = self.inner("endpoint.serve_streams")?;
        let inner = within_runtime_if_available(|| {
            endpoint.serve_streams(move |incoming| {
                let handler = handler.clone();
                Box::pin(async move {
                    let incoming = IncomingStream::from_core(incoming)
                        .map_err(|error| dhttp_napi_error("napi.incoming_stream", error))?;
                    let result = handler
                        .call_async_catch((incoming,).into())
                        .await
                        .map_err(|error| dhttp_napi_error("napi.handler", error))?;
                    if let Either::A(promise) = result {
                        promise
                            .await
                            .map_err(|error| dhttp_napi_error("napi.handler", error))?;
                    }
                    Ok(())
                })
            })
        });
        Ok(ServeHandle { inner: Some(inner) })
    }
}
