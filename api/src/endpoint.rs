use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ddns::resolvers::DnsScheme;
use futures::future::BoxFuture;
use h3x::{
    dquic::{AcceptError, binds::BindPattern},
    error::Code,
    quic::Listen,
    varint::VarInt,
};
use tokio::{
    sync::Mutex as AsyncMutex,
    task::{AbortHandle, JoinHandle},
};
use tower_service::Service;
use tracing::Instrument;

use crate::{error::DhttpError, identity::Identity};

use connection::Connection;

pub mod connection;
pub mod incoming;

pub type Result<T> = std::result::Result<T, DhttpError>;

#[derive(Debug, Clone, Default)]
pub struct EndpointOptions {
    identity: Option<Identity>,
    dns_schemes: Vec<DnsScheme>,
    bind_patterns: Vec<BindPattern>,
}

impl EndpointOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity(&self) -> Option<Identity> {
        self.identity.clone()
    }

    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    pub fn clear_identity(&mut self) {
        self.identity = None;
    }

    pub fn add_dns_scheme(&mut self, scheme: &str) -> Result<()> {
        let scheme = DnsScheme::from_str(scheme)
            .map_err(|error| DhttpError::from_error("endpoint_options.add_dns_scheme", error))?;
        self.dns_schemes.push(scheme);
        Ok(())
    }

    pub fn dns_schemes(&self) -> Vec<String> {
        self.dns_schemes.iter().map(ToString::to_string).collect()
    }

    pub fn add_bind_pattern(&mut self, pattern: &str) -> Result<()> {
        let pattern = BindPattern::from_str(pattern)
            .map_err(|error| DhttpError::from_error("endpoint_options.add_bind_pattern", error))?;
        self.bind_patterns.push(pattern);
        Ok(())
    }

    pub fn bind_patterns(&self) -> Vec<String> {
        self.bind_patterns.iter().map(ToString::to_string).collect()
    }

    pub fn clear_dns_schemes(&mut self) {
        self.dns_schemes.clear();
    }

    pub fn clear_bind_patterns(&mut self) {
        self.bind_patterns.clear();
    }
}

#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<dhttp::endpoint::Endpoint>,
}

impl Endpoint {
    pub async fn create(options: Option<EndpointOptions>) -> Result<Self> {
        let options = options.unwrap_or_default();
        let identity = options
            .identity
            .map(dhttp::identity::Identity::from)
            .map(Arc::new);
        let mut builder = dhttp::endpoint::Endpoint::builder()
            .maybe_identity(identity)
            .bind(Arc::new(options.bind_patterns));
        for scheme in options.dns_schemes {
            builder = builder.dns(scheme);
        }
        Ok(Self {
            inner: Arc::new(
                builder
                    .build()
                    .await
                    .map_err(|error| DhttpError::from_error("endpoint.create", error))?,
            ),
        })
    }

    pub async fn load(name: impl Into<String>) -> Result<Self> {
        dhttp::endpoint::Endpoint::load(name.into())
            .await
            .map(|endpoint| Self {
                inner: Arc::new(endpoint),
            })
            .map_err(|error| DhttpError::from_error("endpoint.load", error))
    }

    pub async fn load_from(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        dhttp::endpoint::Endpoint::load_from(path)
            .await
            .map(|endpoint| Self {
                inner: Arc::new(endpoint),
            })
            .map_err(|error| DhttpError::from_error("endpoint.load_from", error))
    }

    pub fn identity(&self) -> Option<Identity> {
        self.inner
            .identity()
            .as_deref()
            .cloned()
            .map(Identity::from)
    }

    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner
            .bind_patterns()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    pub async fn connect(&self, authority: &str) -> Result<Connection> {
        self.inner
            .connect(authority)
            .await
            .map(Connection::new)
            .map_err(|error| DhttpError::from_error("endpoint.connect", error))
    }

    #[doc(alias = "serve_streams")]
    pub fn listen_streams<H>(&self, handler: H) -> ServeHandle
    where
        H: Fn(incoming::IncomingStream) -> BoxFuture<'static, Result<()>>
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let endpoint = self.inner.clone();
        let service = IncomingStreamService { handler };
        let task = tokio::spawn(async move { endpoint.listen(service).await }.in_current_span());
        ServeHandle::new(self.inner.clone(), task)
    }
}

impl AsRef<dhttp::endpoint::Endpoint> for Endpoint {
    fn as_ref(&self) -> &dhttp::endpoint::Endpoint {
        &self.inner
    }
}

impl From<Arc<dhttp::endpoint::Endpoint>> for Endpoint {
    fn from(inner: Arc<dhttp::endpoint::Endpoint>) -> Self {
        Self { inner }
    }
}

impl From<dhttp::endpoint::Endpoint> for Endpoint {
    fn from(endpoint: dhttp::endpoint::Endpoint) -> Self {
        Self {
            inner: Arc::new(endpoint),
        }
    }
}

impl From<Endpoint> for Arc<dhttp::endpoint::Endpoint> {
    fn from(endpoint: Endpoint) -> Self {
        endpoint.inner
    }
}

pub struct ServeHandle {
    endpoint: Arc<dhttp::endpoint::Endpoint>,
    abort: AbortHandle,
    aborted: AtomicBool,
    task: AsyncMutex<Option<JoinHandle<std::result::Result<(), AcceptError>>>>,
}

impl ServeHandle {
    fn new(
        endpoint: Arc<dhttp::endpoint::Endpoint>,
        task: JoinHandle<std::result::Result<(), AcceptError>>,
    ) -> Self {
        let abort = task.abort_handle();
        Self {
            endpoint,
            abort,
            aborted: AtomicBool::new(false),
            task: AsyncMutex::new(Some(task)),
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        Listen::shutdown(self.endpoint.as_ref())
            .await
            .map_err(|error| DhttpError::from_error("serve_handle.shutdown", error))?;
        self.closed().await
    }

    pub fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
        self.abort.abort();
    }

    pub fn is_finished(&self) -> bool {
        self.task
            .try_lock()
            .ok()
            .is_some_and(|task| task.as_ref().is_none_or(JoinHandle::is_finished))
    }

    pub async fn closed(&self) -> Result<()> {
        let mut guard = self.task.lock().await;
        let Some(task) = guard.as_mut() else {
            return Ok(());
        };
        let result = task.await;
        *guard = None;
        if self.aborted.load(Ordering::SeqCst) {
            return match result {
                Err(error) if !error.is_cancelled() => {
                    Err(DhttpError::from_error("serve_handle.closed", error))
                }
                _ => Ok(()),
            };
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => return Err(DhttpError::from_error("serve_handle.closed", error)),
        };
        result.map_err(|error| DhttpError::from_error("serve_handle.closed", error))
    }
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.abort();
    }
}

#[derive(Clone)]
struct IncomingStreamService<H> {
    handler: H,
}

impl<H> Service<dhttp::endpoint::server::UnresolvedRequest> for IncomingStreamService<H>
where
    H: Fn(incoming::IncomingStream) -> BoxFuture<'static, Result<()>>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Response = ();
    type Error = DhttpError;
    type Future = BoxFuture<'static, Result<()>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: dhttp::endpoint::server::UnresolvedRequest) -> Self::Future {
        let handler = self.handler.clone();
        Box::pin(async move { handler(incoming::IncomingStream::new(req)).await })
    }
}

pub(crate) fn code_from_u64(operation: &'static str, code: u64) -> Result<Code> {
    VarInt::from_u64(code)
        .map(Code::from)
        .map_err(|error| DhttpError::from_error(operation, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serve_handle_closed_clears_failed_join_handle() {
        async fn panic_task() -> std::result::Result<(), AcceptError> {
            panic!("listen task failed");
        }

        let endpoint = Arc::new(dhttp::endpoint::Endpoint::builder().build().await.unwrap());
        let handle = ServeHandle::new(endpoint, tokio::spawn(panic_task()));

        assert!(handle.closed().await.is_err());
        handle.closed().await.unwrap();
        assert!(handle.is_finished());
    }

    #[tokio::test]
    async fn serve_handle_abort_suppresses_completed_accept_error() {
        let endpoint = Arc::new(dhttp::endpoint::Endpoint::builder().build().await.unwrap());
        let (send_complete, recv_complete) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            recv_complete.await.expect("test completion signal");
            Err(AcceptError::ServerUnavailable)
        });
        let handle = ServeHandle::new(endpoint, task);

        send_complete.send(()).expect("test task should be waiting");
        while !handle.is_finished() {
            tokio::task::yield_now().await;
        }
        handle.abort();

        handle.closed().await.unwrap();
    }
}
