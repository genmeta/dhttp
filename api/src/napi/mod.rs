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

    #[napi]
    pub fn sign(&self, scheme: Either<u16, String>, data: Buffer) -> NapiResult<Buffer> {
        let scheme = parse_signature_scheme("identity.sign", scheme)?;
        self.inner
            .sign(scheme, data.as_ref())
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn verify(
        &self,
        scheme: Either<u16, String>,
        data: Buffer,
        signature: Buffer,
    ) -> NapiResult<bool> {
        let scheme = parse_signature_scheme("identity.verify", scheme)?;
        self.inner
            .verify(scheme, data.as_ref(), signature.as_ref())
            .map_err(napi_error)
    }

    #[napi]
    pub fn as_local_authority(&self) -> LocalAuthority {
        LocalAuthority::from(self.inner.as_local_authority())
    }

    #[napi]
    pub fn as_remote_authority(&self) -> RemoteAuthority {
        RemoteAuthority::from(self.inner.as_remote_authority())
    }
}

fn parse_signature_scheme(operation: &'static str, value: Either<u16, String>) -> NapiResult<u16> {
    match value {
        Either::A(code) => Ok(code),
        Either::B(name) => crate::signature_scheme::parse_name(&name)
            .map_err(|error| napi_error(crate::error::DhttpError::from_error(operation, error))),
    }
}

#[napi(js_name = "LocalAuthority")]
pub struct LocalAuthority {
    inner: crate::authority::LocalAuthority,
}

impl From<crate::authority::LocalAuthority> for LocalAuthority {
    fn from(inner: crate::authority::LocalAuthority) -> Self {
        Self { inner }
    }
}

#[napi]
impl LocalAuthority {
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

    #[napi]
    pub async fn sign(&self, scheme: Either<u16, String>, data: Buffer) -> NapiResult<Buffer> {
        let scheme = parse_signature_scheme("local_authority.sign", scheme)?;
        let data = data.as_ref().to_vec();
        self.inner
            .sign(scheme, data)
            .await
            .map(Buffer::from)
            .map_err(napi_error)
    }

    #[napi]
    pub async fn verify(
        &self,
        scheme: Either<u16, String>,
        data: Buffer,
        signature: Buffer,
    ) -> NapiResult<bool> {
        let scheme = parse_signature_scheme("local_authority.verify", scheme)?;
        let data = data.as_ref().to_vec();
        let signature = signature.as_ref().to_vec();
        self.inner
            .verify(scheme, data, signature)
            .await
            .map_err(napi_error)
    }
}

#[napi(js_name = "RemoteAuthority")]
pub struct RemoteAuthority {
    inner: crate::authority::RemoteAuthority,
}

impl From<crate::authority::RemoteAuthority> for RemoteAuthority {
    fn from(inner: crate::authority::RemoteAuthority) -> Self {
        Self { inner }
    }
}

#[napi]
impl RemoteAuthority {
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

    #[napi]
    pub async fn verify(
        &self,
        scheme: Either<u16, String>,
        data: Buffer,
        signature: Buffer,
    ) -> NapiResult<bool> {
        let scheme = parse_signature_scheme("remote_authority.verify", scheme)?;
        let data = data.as_ref().to_vec();
        let signature = signature.as_ref().to_vec();
        self.inner
            .verify(scheme, data, signature)
            .await
            .map_err(napi_error)
    }
}

#[napi(js_name = "DhttpHome")]
pub struct DhttpHome {
    inner: crate::home::DhttpHome,
}

#[napi]
impl DhttpHome {
    #[napi(constructor)]
    pub fn new(path: String) -> Self {
        Self {
            inner: crate::home::DhttpHome::from_path(path),
        }
    }

    #[napi]
    pub fn load() -> NapiResult<DhttpHome> {
        crate::home::DhttpHome::load()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi]
    pub fn identity_profile(&self, name: String) -> NapiResult<IdentityProfile> {
        self.inner
            .identity_profile(&name)
            .map(|inner| IdentityProfile { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn resolve_identity_profile(&self, name: String) -> NapiResult<IdentityProfile> {
        self.inner
            .resolve_identity_profile(&name)
            .await
            .map(|inner| IdentityProfile { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn identity_profile_exists(&self, name: String) -> NapiResult<bool> {
        self.inner
            .identity_profile_exists(&name)
            .await
            .map_err(napi_error)
    }

    #[napi]
    pub async fn identity_profile_names(&self) -> NapiResult<Vec<String>> {
        self.inner
            .identity_profile_names()
            .await
            .map_err(napi_error)
    }
}

#[napi(js_name = "IdentityProfile")]
pub struct IdentityProfile {
    inner: crate::home::IdentityProfile,
}

#[napi]
impl IdentityProfile {
    #[napi]
    pub fn from_path(path: String) -> NapiResult<IdentityProfile> {
        crate::home::IdentityProfile::from_path(path)
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
    pub async fn load_identity(&self) -> NapiResult<Identity> {
        self.inner
            .load_identity()
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
    state: Mutex<ReadStreamState>,
}

struct ActiveRead {
    stop: Option<StopCodeSender>,
    done: Option<StopDoneReceiver>,
    stop_requested: Option<u64>,
}

type StopCodeSender = tokio::sync::oneshot::Sender<u64>;
type StopCodeReceiver = tokio::sync::oneshot::Receiver<u64>;
type StopDoneSender =
    tokio::sync::oneshot::Sender<std::result::Result<(), crate::error::DhttpError>>;
type StopDoneReceiver =
    tokio::sync::oneshot::Receiver<std::result::Result<(), crate::error::DhttpError>>;
type StartedRead = (crate::stream::ReadStream, StopCodeReceiver, StopDoneSender);

struct ReadStreamState {
    inner: Option<crate::stream::ReadStream>,
    active: Option<ActiveRead>,
    closed: bool,
}

enum FinishRead {
    Restored,
    Stop(crate::stream::ReadStream, u64),
}

struct ActiveReadCleanup<'a> {
    stream: &'a ReadStream,
    operation: &'static str,
    done: Option<StopDoneSender>,
    armed: bool,
}

impl<'a> ActiveReadCleanup<'a> {
    fn new(stream: &'a ReadStream, operation: &'static str, done: StopDoneSender) -> Self {
        Self {
            stream,
            operation,
            done: Some(done),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.done = None;
    }

    fn take_done(&mut self) -> NapiResult<StopDoneSender> {
        self.done
            .take()
            .ok_or_else(|| state_error(self.operation, "read stream stop completion is missing"))
    }
}

impl Drop for ActiveReadCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        {
            let mut state = self
                .stream
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = None;
            state.inner = None;
            state.closed = true;
        }

        if let Some(done) = self.done.take() {
            _ = done.send(Err(crate::error::DhttpError::from_message(
                self.operation,
                "read stream read was cancelled",
            )));
        }
    }
}

impl From<crate::stream::ReadStream> for ReadStream {
    fn from(inner: crate::stream::ReadStream) -> Self {
        Self {
            state: Mutex::new(ReadStreamState {
                inner: Some(inner),
                active: None,
                closed: false,
            }),
        }
    }
}

impl Drop for ReadStream {
    fn drop(&mut self) {
        let inner = match self.state.get_mut() {
            Ok(state) => state.inner.take(),
            Err(poisoned) => poisoned.into_inner().inner.take(),
        };
        if let Some(inner) = inner {
            drop_with_napi_runtime(inner);
        }
    }
}

impl ReadStream {
    fn start_read(&self, operation: &'static str) -> NapiResult<StartedRead> {
        let mut state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => state_error(operation, "read stream is busy"),
            std::sync::TryLockError::Poisoned(_) => {
                state_error(operation, "read stream mutex is poisoned")
            }
        })?;
        let inner = state.inner.take().ok_or_else(|| {
            if state.closed {
                state_error(operation, "read stream is closed")
            } else {
                state_error(operation, "read stream is busy")
            }
        })?;
        let (stop, stop_requested) = tokio::sync::oneshot::channel();
        let (done, done_requested) = tokio::sync::oneshot::channel();
        state.active = Some(ActiveRead {
            stop: Some(stop),
            done: Some(done_requested),
            stop_requested: None,
        });
        Ok((inner, stop_requested, done))
    }

    fn finish_read(&self, inner: crate::stream::ReadStream) -> FinishRead {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(code) = state
            .active
            .as_ref()
            .and_then(|active| active.stop_requested)
        {
            state.active = None;
            return FinishRead::Stop(inner, code);
        }
        state.active = None;
        state.inner = Some(inner);
        FinishRead::Restored
    }

    fn close_after_stop(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = None;
        state.inner = None;
        state.closed = true;
    }

    async fn interrupt_active_or_stop_inner(
        &self,
        operation: &'static str,
        code: u64,
    ) -> NapiResult<()> {
        enum StopTarget {
            Inner(crate::stream::ReadStream),
            Active {
                stop: Option<StopCodeSender>,
                done: StopDoneReceiver,
            },
        }

        let target = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| state_error(operation, "read stream mutex is poisoned"))?;

            if let Some(inner) = state.inner.take() {
                StopTarget::Inner(inner)
            } else if let Some(active) = state.active.as_mut() {
                if active.stop_requested.is_some() {
                    return Err(state_error(
                        operation,
                        "read stream stop is already pending",
                    ));
                }
                active.stop_requested = Some(code);
                let stop = active.stop.take();
                let done = active
                    .done
                    .take()
                    .ok_or_else(|| state_error(operation, "read stream stop is already pending"))?;
                StopTarget::Active { stop, done }
            } else if state.closed {
                return Err(state_error(operation, "read stream is closed"));
            } else {
                return Err(state_error(operation, "read stream is busy"));
            }
        };

        match target {
            StopTarget::Inner(mut inner) => {
                let result = inner.stop(code).await;
                self.close_after_stop();
                result.map_err(napi_error)
            }
            StopTarget::Active { stop, done } => {
                if let Some(stop) = stop {
                    _ = stop.send(code);
                }
                match done.await {
                    Ok(result) => result.map_err(napi_error),
                    Err(_) => Err(state_error(operation, "read stream stop was interrupted")),
                }
            }
        }
    }

    async fn finish_interrupted_read(
        &self,
        mut inner: crate::stream::ReadStream,
        code: u64,
        done: StopDoneSender,
    ) -> NapiResult<()> {
        let result = inner.stop(code).await;
        self.close_after_stop();
        let read_result = result.clone();
        _ = done.send(result);
        read_result.map_err(napi_error)
    }
}

#[napi]
impl ReadStream {
    #[napi]
    pub async fn read_data_frame_chunk(&self) -> NapiResult<Option<Vec<u8>>> {
        let operation = "read_stream.read_data_frame_chunk";
        let (mut inner, stop_requested, done) = self.start_read(operation)?;
        let mut cleanup = ActiveReadCleanup::new(self, operation, done);
        tokio::select! {
            biased;
            code = stop_requested => {
                let code = code.unwrap_or(0);
                let done = cleanup.take_done()?;
                self.finish_interrupted_read(inner, code, done).await?;
                cleanup.disarm();
                Ok(None)
            }
            result = inner.read_data_frame_chunk() => {
                match self.finish_read(inner) {
                    FinishRead::Restored => {
                        cleanup.disarm();
                        result.map_err(napi_error)
                    }
                    FinishRead::Stop(inner, code) => {
                        let done = cleanup.take_done()?;
                        self.finish_interrupted_read(inner, code, done).await?;
                        cleanup.disarm();
                        Ok(None)
                    }
                }
            }
        }
    }

    #[napi]
    pub async fn read_header_frame(&self) -> NapiResult<Option<Vec<HeaderField>>> {
        let operation = "read_stream.read_header_frame";
        let (mut inner, stop_requested, done) = self.start_read(operation)?;
        let mut cleanup = ActiveReadCleanup::new(self, operation, done);
        tokio::select! {
            biased;
            code = stop_requested => {
                let code = code.unwrap_or(0);
                let done = cleanup.take_done()?;
                self.finish_interrupted_read(inner, code, done).await?;
                cleanup.disarm();
                Ok(None)
            }
            result = inner.read_header_frame() => {
                match self.finish_read(inner) {
                    FinishRead::Restored => {
                        cleanup.disarm();
                        result
                            .map(|headers| {
                                headers.map(|headers| headers.into_iter().map(HeaderField::from_pair).collect())
                            })
                            .map_err(napi_error)
                    }
                    FinishRead::Stop(inner, code) => {
                        let done = cleanup.take_done()?;
                        self.finish_interrupted_read(inner, code, done).await?;
                        cleanup.disarm();
                        Ok(None)
                    }
                }
            }
        }
    }

    #[napi]
    pub async fn stop(&self, code: u32) -> NapiResult<()> {
        self.interrupt_active_or_stop_inner("read_stream.stop", u64::from(code))
            .await
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
    pub async fn reset(&self, code: u32) -> NapiResult<()> {
        let operation = "write_stream.reset";
        let mut inner = self.take_inner(operation)?;
        match inner.reset(u64::from(code)).await {
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

    #[napi]
    pub async fn local_authority(&self) -> NapiResult<Option<LocalAuthority>> {
        self.inner
            .local_authority()
            .await
            .map(|opt| opt.map(LocalAuthority::from))
            .map_err(napi_error)
    }

    #[napi]
    pub async fn remote_authority(&self) -> NapiResult<Option<RemoteAuthority>> {
        self.inner
            .remote_authority()
            .await
            .map(|opt| opt.map(RemoteAuthority::from))
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
    pub fn listen_streams(
        &self,
        handler: Function<StreamHandlerArgs, StreamHandlerResult>,
    ) -> NapiResult<ServeHandle> {
        let handler = handler
            .build_threadsafe_function::<StreamHandlerArgs>()
            .callee_handled::<false>()
            .build()?;
        let handler = Arc::new(handler);
        let endpoint = self.inner("endpoint.listen_streams")?;
        let inner = within_runtime_if_available(|| {
            endpoint.listen_streams(move |incoming| {
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
