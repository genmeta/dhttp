use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use ::pyo3::{exceptions::PyRuntimeError, prelude::*};
use futures::{FutureExt, future::BoxFuture};

fn py_error(error: crate::error::DhttpError) -> PyErr {
    PyRuntimeError::new_err(error.report().to_owned())
}

fn dhttp_py_error(operation: &'static str, error: PyErr) -> crate::error::DhttpError {
    crate::error::DhttpError::from_error(operation, error)
}

fn state_error(operation: &'static str, message: &'static str) -> PyErr {
    py_error(crate::error::DhttpError::from_message(operation, message))
}

static DROP_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to create dhttp pyo3 drop runtime")
});

fn drop_with_pyo3_runtime<T>(value: T) {
    let _guard = DROP_RUNTIME.enter();
    drop(value);
}

async fn wait_python_result(
    result: Py<PyAny>,
    locals: Option<pyo3_async_runtimes::TaskLocals>,
) -> PyResult<()> {
    let future = Python::attach(
        |py| -> PyResult<Option<BoxFuture<'static, PyResult<Py<PyAny>>>>> {
            let is_awaitable = py
                .import("inspect")?
                .call_method1("isawaitable", (result.bind(py),))?
                .extract()?;
            if is_awaitable {
                let locals = locals.as_ref().ok_or_else(|| {
                    PyRuntimeError::new_err("async dhttp handler requires a running asyncio task")
                })?;
                let future =
                    pyo3_async_runtimes::into_future_with_locals(locals, result.into_bound(py))?;
                Ok(Some(future.boxed()))
            } else {
                Ok(None)
            }
        },
    )?;
    if let Some(future) = future {
        future.await?;
    }
    Ok(())
}

async fn with_tokio<F>(future: F) -> F::Output
where
    F: Future + Send,
{
    TokioContextFuture {
        future: Box::pin(future),
    }
    .await
}

struct TokioContextFuture<F> {
    future: Pin<Box<F>>,
}

impl<F> Future for TokioContextFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _guard = pyo3_async_runtimes::tokio::get_runtime().enter();
        self.future.as_mut().poll(cx)
    }
}

#[pyclass(name = "Identity")]
pub struct Identity {
    inner: crate::identity::Identity,
}

impl From<crate::identity::Identity> for Identity {
    fn from(inner: crate::identity::Identity) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Identity {
    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner.cert_chain_der()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key_der()
    }

    pub fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        self.inner.sign(&data).map_err(py_error)
    }

    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        self.inner.verify(&data, &signature).map_err(py_error)
    }

    pub fn as_local_authority(&self) -> LocalAuthority {
        LocalAuthority::from(self.inner.as_local_authority())
    }

    pub fn as_remote_authority(&self) -> RemoteAuthority {
        RemoteAuthority::from(self.inner.as_remote_authority())
    }
}

#[pyclass(name = "LocalAuthority", skip_from_py_object)]
#[derive(Clone)]
pub struct LocalAuthority {
    inner: crate::authority::LocalAuthority,
}

impl From<crate::authority::LocalAuthority> for LocalAuthority {
    fn from(inner: crate::authority::LocalAuthority) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl LocalAuthority {
    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner.cert_chain_der()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key_der()
    }

    pub async fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        let inner = self.inner.clone();
        with_tokio(async move { inner.sign(data).await })
            .await
            .map_err(py_error)
    }

    pub async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let inner = self.inner.clone();
        with_tokio(async move { inner.verify(data, signature).await })
            .await
            .map_err(py_error)
    }
}

#[pyclass(name = "RemoteAuthority", skip_from_py_object)]
#[derive(Clone)]
pub struct RemoteAuthority {
    inner: crate::authority::RemoteAuthority,
}

impl From<crate::authority::RemoteAuthority> for RemoteAuthority {
    fn from(inner: crate::authority::RemoteAuthority) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl RemoteAuthority {
    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn cert_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner.cert_chain_der()
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.inner.public_key_der()
    }

    pub async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let inner = self.inner.clone();
        with_tokio(async move { inner.verify(data, signature).await })
            .await
            .map_err(py_error)
    }
}

#[pyclass(name = "DhttpHome")]
pub struct DhttpHome {
    inner: crate::home::DhttpHome,
}

#[pymethods]
impl DhttpHome {
    #[new]
    pub fn new(path: String) -> Self {
        Self {
            inner: crate::home::DhttpHome::from_path(path),
        }
    }

    #[staticmethod]
    pub fn load() -> PyResult<Self> {
        crate::home::DhttpHome::load()
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    pub fn identity_profile(&self, name: String) -> PyResult<IdentityProfile> {
        self.inner
            .identity_profile(&name)
            .map(|inner| IdentityProfile { inner })
            .map_err(py_error)
    }

    pub async fn resolve_identity_profile(&self, name: String) -> PyResult<IdentityProfile> {
        with_tokio(self.inner.resolve_identity_profile(&name))
            .await
            .map(|inner| IdentityProfile { inner })
            .map_err(py_error)
    }

    pub async fn identity_profile_exists(&self, name: String) -> PyResult<bool> {
        with_tokio(self.inner.identity_profile_exists(&name))
            .await
            .map_err(py_error)
    }

    pub async fn identity_profile_names(&self) -> PyResult<Vec<String>> {
        with_tokio(self.inner.identity_profile_names())
            .await
            .map_err(py_error)
    }
}

#[pyclass(name = "IdentityProfile")]
pub struct IdentityProfile {
    inner: crate::home::IdentityProfile,
}

#[pymethods]
impl IdentityProfile {
    #[new]
    pub fn new(path: String) -> PyResult<Self> {
        crate::home::IdentityProfile::from_path(path)
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    pub async fn load_identity(&self) -> PyResult<Identity> {
        with_tokio(self.inner.load_identity())
            .await
            .map(Identity::from)
            .map_err(py_error)
    }
}

#[pyclass(name = "EndpointOptions")]
pub struct EndpointOptions {
    inner: crate::endpoint::EndpointOptions,
}

#[pymethods]
impl EndpointOptions {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: crate::endpoint::EndpointOptions::new(),
        }
    }

    pub fn identity(&self) -> Option<Identity> {
        self.inner.identity().map(Identity::from)
    }

    pub fn set_identity(&mut self, identity: &Identity) {
        self.inner.set_identity(identity.inner.clone());
    }

    pub fn clear_identity(&mut self) {
        self.inner.clear_identity();
    }

    pub fn add_dns_scheme(&mut self, scheme: String) -> PyResult<()> {
        self.inner.add_dns_scheme(&scheme).map_err(py_error)
    }

    pub fn dns_schemes(&self) -> Vec<String> {
        self.inner.dns_schemes()
    }

    pub fn clear_dns_schemes(&mut self) {
        self.inner.clear_dns_schemes();
    }

    pub fn add_bind_pattern(&mut self, pattern: String) -> PyResult<()> {
        self.inner.add_bind_pattern(&pattern).map_err(py_error)
    }

    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner.bind_patterns()
    }

    pub fn clear_bind_patterns(&mut self) {
        self.inner.clear_bind_patterns();
    }
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[pyclass(name = "MessageReader")]
pub struct MessageReader {
    state: Mutex<MessageReaderState>,
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

struct MessageReaderState {
    inner: Option<crate::stream::ReadStream>,
    active: Option<ActiveRead>,
    closed: bool,
}

enum FinishRead {
    Restored,
    Stop(crate::stream::ReadStream, u64),
}

struct ActiveReadCleanup<'a> {
    stream: &'a MessageReader,
    operation: &'static str,
    done: Option<StopDoneSender>,
    armed: bool,
}

impl<'a> ActiveReadCleanup<'a> {
    fn new(stream: &'a MessageReader, operation: &'static str, done: StopDoneSender) -> Self {
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

    fn take_done(&mut self) -> PyResult<StopDoneSender> {
        self.done
            .take()
            .ok_or_else(|| state_error(self.operation, "message reader stop completion is missing"))
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
                "message reader read was cancelled",
            )));
        }
    }
}

impl From<crate::stream::ReadStream> for MessageReader {
    fn from(inner: crate::stream::ReadStream) -> Self {
        Self {
            state: Mutex::new(MessageReaderState {
                inner: Some(inner),
                active: None,
                closed: false,
            }),
        }
    }
}

impl Drop for MessageReader {
    fn drop(&mut self) {
        let inner = match self.state.get_mut() {
            Ok(state) => state.inner.take(),
            Err(poisoned) => poisoned.into_inner().inner.take(),
        };
        if let Some(inner) = inner {
            drop_with_pyo3_runtime(inner);
        }
    }
}

impl MessageReader {
    fn start_read(&self, operation: &'static str) -> PyResult<StartedRead> {
        let mut state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => state_error(operation, "message reader is busy"),
            std::sync::TryLockError::Poisoned(_) => {
                state_error(operation, "message reader mutex is poisoned")
            }
        })?;
        let inner = state.inner.take().ok_or_else(|| {
            if state.closed {
                state_error(operation, "message reader is closed")
            } else {
                state_error(operation, "message reader is busy")
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
    ) -> PyResult<()> {
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
                .map_err(|_| state_error(operation, "message reader mutex is poisoned"))?;

            if let Some(inner) = state.inner.take() {
                StopTarget::Inner(inner)
            } else if let Some(active) = state.active.as_mut() {
                if active.stop_requested.is_some() {
                    return Err(state_error(
                        operation,
                        "message reader stop is already pending",
                    ));
                }
                active.stop_requested = Some(code);
                let stop = active.stop.take();
                let done = active.done.take().ok_or_else(|| {
                    state_error(operation, "message reader stop is already pending")
                })?;
                StopTarget::Active { stop, done }
            } else if state.closed {
                return Err(state_error(operation, "message reader is closed"));
            } else {
                return Err(state_error(operation, "message reader is busy"));
            }
        };

        match target {
            StopTarget::Inner(mut inner) => {
                let result = with_tokio(inner.stop(code)).await;
                self.close_after_stop();
                result.map_err(py_error)
            }
            StopTarget::Active { stop, done } => {
                if let Some(stop) = stop {
                    _ = stop.send(code);
                }
                match done.await {
                    Ok(result) => result.map_err(py_error),
                    Err(_) => Err(state_error(
                        operation,
                        "message reader stop was interrupted",
                    )),
                }
            }
        }
    }

    async fn finish_interrupted_read(
        &self,
        mut inner: crate::stream::ReadStream,
        code: u64,
        done: StopDoneSender,
    ) -> PyResult<()> {
        let result = inner.stop(code).await;
        self.close_after_stop();
        let read_result = result.clone();
        _ = done.send(result);
        read_result.map_err(py_error)
    }
}

#[pymethods]
impl MessageReader {
    pub async fn read_data(&self) -> PyResult<Option<Vec<u8>>> {
        let operation = "message_reader.read_data";
        let (mut inner, stop_requested, done) = self.start_read(operation)?;
        let mut cleanup = ActiveReadCleanup::new(self, operation, done);
        with_tokio(async move {
            tokio::select! {
                biased;
                code = stop_requested => {
                    let code = code.unwrap_or(0);
                    let done = cleanup.take_done()?;
                    self.finish_interrupted_read(inner, code, done).await?;
                    cleanup.disarm();
                    Ok(None)
                }
                result = inner.read_data() => {
                    match self.finish_read(inner) {
                        FinishRead::Restored => {
                            cleanup.disarm();
                            result.map_err(py_error)
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
        })
        .await
    }

    pub async fn read_header(&self) -> PyResult<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let operation = "message_reader.read_header";
        let (mut inner, stop_requested, done) = self.start_read(operation)?;
        let mut cleanup = ActiveReadCleanup::new(self, operation, done);
        with_tokio(async move {
            tokio::select! {
                biased;
                code = stop_requested => {
                    let code = code.unwrap_or(0);
                    let done = cleanup.take_done()?;
                    self.finish_interrupted_read(inner, code, done).await?;
                    cleanup.disarm();
                    Ok(None)
                }
                result = inner.read_header() => {
                    match self.finish_read(inner) {
                        FinishRead::Restored => {
                            cleanup.disarm();
                            result.map_err(py_error)
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
        })
        .await
    }

    pub async fn stop(&self, code: u64) -> PyResult<()> {
        self.interrupt_active_or_stop_inner("message_reader.stop", code)
            .await
    }
}

#[pyclass(name = "MessageWriter")]
pub struct MessageWriter {
    inner: Mutex<Option<crate::stream::WriteStream>>,
    closed: AtomicBool,
}

impl From<crate::stream::WriteStream> for MessageWriter {
    fn from(inner: crate::stream::WriteStream) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            closed: AtomicBool::new(false),
        }
    }
}

impl Drop for MessageWriter {
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(inner) => inner.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(inner) = inner {
            drop_with_pyo3_runtime(inner);
        }
    }
}

impl MessageWriter {
    fn take_inner(&self, operation: &'static str) -> PyResult<crate::stream::WriteStream> {
        let mut guard = self.inner.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => state_error(operation, "message writer is busy"),
            std::sync::TryLockError::Poisoned(_) => {
                state_error(operation, "message writer mutex is poisoned")
            }
        })?;
        guard.take().ok_or_else(|| {
            if self.closed.load(Ordering::SeqCst) {
                state_error(operation, "message writer is closed")
            } else {
                state_error(operation, "message writer is busy")
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

#[pymethods]
impl MessageWriter {
    pub async fn write_header(&self, headers: Vec<(Vec<u8>, Vec<u8>)>) -> PyResult<()> {
        let operation = "message_writer.write_header";
        let mut inner = self.take_inner(operation)?;
        let result = with_tokio(inner.write_header(headers)).await;
        self.restore_inner(inner);
        result.map_err(py_error)
    }

    pub async fn write_data(&self, data: Vec<u8>) -> PyResult<()> {
        let operation = "message_writer.write_data";
        let mut inner = self.take_inner(operation)?;
        let result = with_tokio(inner.write_data(data)).await;
        self.restore_inner(inner);
        result.map_err(py_error)
    }

    pub async fn flush(&self) -> PyResult<()> {
        let operation = "message_writer.flush";
        let mut inner = self.take_inner(operation)?;
        let result = with_tokio(inner.flush()).await;
        self.restore_inner(inner);
        result.map_err(py_error)
    }

    pub async fn close(&self) -> PyResult<()> {
        let operation = "message_writer.close";
        let mut inner = self.take_inner(operation)?;
        match with_tokio(inner.close()).await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.restore_inner(inner);
                Err(py_error(error))
            }
        }
    }

    pub async fn reset(&self, code: u64) -> PyResult<()> {
        let operation = "message_writer.reset";
        let mut inner = self.take_inner(operation)?;
        match with_tokio(inner.reset(code)).await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.restore_inner(inner);
                Err(py_error(error))
            }
        }
    }
}

#[pyclass(name = "UnresolvedRequest")]
pub struct UnresolvedRequest {
    stream_id: u64,
    reader: Mutex<Option<MessageReader>>,
    writer: Mutex<Option<MessageWriter>>,
    local_authority: Option<LocalAuthority>,
    remote_authority: Option<RemoteAuthority>,
}

impl UnresolvedRequest {
    fn from_core(request: crate::endpoint::unresolved::UnresolvedRequest) -> PyResult<Self> {
        let stream_id = request.stream_id();
        let local_authority = request.local_authority().map(LocalAuthority::from);
        let remote_authority = request.remote_authority().map(RemoteAuthority::from);
        let (reader, writer) = request.into_parts();
        Ok(Self {
            stream_id,
            reader: Mutex::new(Some(MessageReader::from(reader))),
            writer: Mutex::new(Some(MessageWriter::from(writer))),
            local_authority,
            remote_authority,
        })
    }

    fn take_reader(&self) -> PyResult<MessageReader> {
        self.reader
            .lock()
            .map_err(|_| {
                state_error(
                    "unresolved_request.reader",
                    "unresolved request mutex is poisoned",
                )
            })?
            .take()
            .ok_or_else(|| state_error("unresolved_request.reader", "message reader is closed"))
    }

    fn take_writer(&self) -> PyResult<MessageWriter> {
        self.writer
            .lock()
            .map_err(|_| {
                state_error(
                    "unresolved_request.writer",
                    "unresolved request mutex is poisoned",
                )
            })?
            .take()
            .ok_or_else(|| state_error("unresolved_request.writer", "message writer is closed"))
    }
}

#[pymethods]
impl UnresolvedRequest {
    #[getter]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    #[getter]
    pub fn reader(&self) -> PyResult<MessageReader> {
        self.take_reader()
    }

    #[getter]
    pub fn writer(&self) -> PyResult<MessageWriter> {
        self.take_writer()
    }

    pub fn local_authority(&self) -> Option<LocalAuthority> {
        self.local_authority.clone()
    }

    pub fn remote_authority(&self) -> Option<RemoteAuthority> {
        self.remote_authority.clone()
    }
}

#[pyclass(name = "Connection")]
pub struct Connection {
    inner: crate::endpoint::connection::Connection,
}

impl From<crate::endpoint::connection::Connection> for Connection {
    fn from(inner: crate::endpoint::connection::Connection) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Connection {
    pub async fn open_request(&self) -> PyResult<UnresolvedRequest> {
        let inner = self.inner.clone();
        let request = with_tokio(async move { inner.open_request().await })
            .await
            .map_err(py_error)?;
        UnresolvedRequest::from_core(request)
    }

    pub async fn local_authority(&self) -> PyResult<Option<LocalAuthority>> {
        let inner = self.inner.clone();
        with_tokio(async move { inner.local_authority().await })
            .await
            .map(|opt| opt.map(LocalAuthority::from))
            .map_err(py_error)
    }

    pub async fn remote_authority(&self) -> PyResult<Option<RemoteAuthority>> {
        let inner = self.inner.clone();
        with_tokio(async move { inner.remote_authority().await })
            .await
            .map(|opt| opt.map(RemoteAuthority::from))
            .map_err(py_error)
    }
}

#[pyclass(name = "ServeHandle")]
pub struct ServeHandle {
    inner: Option<crate::endpoint::ServeHandle>,
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop_with_pyo3_runtime(inner);
        }
    }
}

impl ServeHandle {
    fn inner(&self, operation: &'static str) -> PyResult<&crate::endpoint::ServeHandle> {
        self.inner
            .as_ref()
            .ok_or_else(|| state_error(operation, "serve handle is closed"))
    }
}

#[pymethods]
impl ServeHandle {
    pub async fn shutdown(&self) -> PyResult<()> {
        with_tokio(self.inner("serve_handle.shutdown")?.shutdown())
            .await
            .map_err(py_error)
    }

    pub fn abort(&self) {
        if let Some(inner) = &self.inner {
            inner.abort();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.inner.as_ref().is_none_or(|inner| inner.is_finished())
    }

    pub async fn closed(&self) -> PyResult<()> {
        with_tokio(self.inner("serve_handle.closed")?.closed())
            .await
            .map_err(py_error)
    }
}

#[pyclass(name = "Endpoint")]
pub struct Endpoint {
    inner: Option<crate::endpoint::Endpoint>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop_with_pyo3_runtime(inner);
        }
    }
}

impl Endpoint {
    fn inner(&self, operation: &'static str) -> PyResult<&crate::endpoint::Endpoint> {
        self.inner
            .as_ref()
            .ok_or_else(|| state_error(operation, "endpoint is closed"))
    }
}

#[pymethods]
impl Endpoint {
    #[staticmethod]
    pub async fn create(options: Option<&EndpointOptions>) -> PyResult<Self> {
        let options = options.map(|options| options.inner.clone());
        with_tokio(crate::endpoint::Endpoint::create(options))
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(py_error)
    }

    #[staticmethod]
    pub async fn load(name: String) -> PyResult<Self> {
        with_tokio(crate::endpoint::Endpoint::load(name))
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(py_error)
    }

    #[staticmethod]
    pub async fn load_from(path: String) -> PyResult<Self> {
        with_tokio(crate::endpoint::Endpoint::load_from(path))
            .await
            .map(|inner| Self { inner: Some(inner) })
            .map_err(py_error)
    }

    pub fn identity(&self) -> Option<Identity> {
        self.inner
            .as_ref()
            .and_then(crate::endpoint::Endpoint::identity)
            .map(Identity::from)
    }

    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner
            .as_ref()
            .map(crate::endpoint::Endpoint::bind_patterns)
            .unwrap_or_default()
    }

    pub async fn connect(&self, authority: String) -> PyResult<Connection> {
        let endpoint = self.inner("endpoint.connect")?.clone();
        with_tokio(async move { endpoint.connect(&authority).await })
            .await
            .map(Connection::from)
            .map_err(py_error)
    }

    pub fn listen_raw(&self, handler: Py<PyAny>) -> PyResult<ServeHandle> {
        let locals = Python::attach(|py| pyo3_async_runtimes::tokio::get_current_locals(py).ok());
        let handler = Arc::new(handler);
        let endpoint = self.inner("endpoint.listen_raw")?;
        let _guard = pyo3_async_runtimes::tokio::get_runtime().enter();
        let inner = endpoint.listen_raw(move |request| {
            let handler = handler.clone();
            let locals = locals.clone();
            Box::pin(async move {
                let request = UnresolvedRequest::from_core(request)
                    .map_err(|error| dhttp_py_error("pyo3.unresolved_request", error))?;
                let result = Python::attach(|py| -> PyResult<Py<PyAny>> {
                    let request = Py::new(py, request)?;
                    handler.as_ref().call1(py, (request,))
                })
                .map_err(|error| dhttp_py_error("pyo3.handler", error))?;
                wait_python_result(result, locals)
                    .await
                    .map_err(|error| dhttp_py_error("pyo3.handler", error))?;
                Ok(())
            })
        });
        Ok(ServeHandle { inner: Some(inner) })
    }
}

#[pymodule]
pub fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Identity>()?;
    module.add_class::<LocalAuthority>()?;
    module.add_class::<RemoteAuthority>()?;
    module.add_class::<DhttpHome>()?;
    module.add_class::<IdentityProfile>()?;
    module.add_class::<EndpointOptions>()?;
    module.add_class::<MessageReader>()?;
    module.add_class::<MessageWriter>()?;
    module.add_class::<UnresolvedRequest>()?;
    module.add_class::<Connection>()?;
    module.add_class::<ServeHandle>()?;
    module.add_class::<Endpoint>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::wait_python_result;

    use pyo3::{prelude::*, types::PyDict};

    #[test]
    fn wait_python_result_drives_asyncio_awaitable_from_rust_future() {
        Python::initialize();
        Python::attach(|py| {
            pyo3_async_runtimes::tokio::run(py, async move {
                let (coroutine, task_locals) = Python::attach(|py| {
                    let locals = PyDict::new(py);
                    py.run(
                        c"
import asyncio

async def handler():
    await asyncio.sleep(0)
    return 'ok'
",
                        Some(&locals),
                        Some(&locals),
                    )?;
                    let coroutine = py
                        .eval(c"handler()", Some(&locals), Some(&locals))?
                        .unbind();
                    let task_locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
                    PyResult::Ok((coroutine, task_locals))
                })?;
                wait_python_result(coroutine, Some(task_locals))
                    .await
                    .unwrap();
                Ok(())
            })
            .unwrap();
        });
    }
}
