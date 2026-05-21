use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use dhttp::{
    ddns::DnsScheme,
    dquic::binds::BindPattern,
    h3x::{error::Code, quic::Listen, varint::VarInt},
};
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use tokio::{
    sync::Mutex as AsyncMutex,
    task::{AbortHandle, JoinHandle},
};
use tower_service::Service;
use tracing::Instrument;

use crate::{error::DhttpError, identity::Identity};

pub mod client;
pub mod server;

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
            inner: Arc::new(builder.build().await),
        })
    }

    pub async fn load(name: &str) -> Result<Self> {
        dhttp::endpoint::Endpoint::load(name)
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

    pub fn request(&self) -> client::Request {
        client::Request::new(self.inner.new_request())
    }

    pub fn get(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::GET, uri, "endpoint.get")
    }

    pub fn post(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::POST, uri, "endpoint.post")
    }

    pub fn put(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::PUT, uri, "endpoint.put")
    }

    pub fn delete(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::DELETE, uri, "endpoint.delete")
    }

    pub fn patch(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::PATCH, uri, "endpoint.patch")
    }

    pub fn head(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::HEAD, uri, "endpoint.head")
    }

    pub fn options(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::OPTIONS, uri, "endpoint.options")
    }

    pub fn trace(&self, uri: &str) -> Result<client::Request> {
        self.method_request(Method::TRACE, uri, "endpoint.trace")
    }

    fn method_request(
        &self,
        method: Method,
        uri: &str,
        operation: &'static str,
    ) -> Result<client::Request> {
        let request = self.request();
        request.set_method_value(method);
        request.set_uri_value(parse_uri(operation, uri)?);
        Ok(request)
    }

    pub fn serve<H>(&self, handler: H) -> ServeHandle
    where
        H: for<'a> Fn(&'a server::Request, &'a server::Response) -> BoxFuture<'a, Result<()>>
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let endpoint = self.inner.clone();
        let service = HandlerService { handler };
        let task = tokio::spawn(async move { endpoint.serve(service).await }.in_current_span());
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
    task: AsyncMutex<Option<JoinHandle<std::result::Result<(), dhttp::dquic::AcceptError>>>>,
}

impl ServeHandle {
    fn new(
        endpoint: Arc<dhttp::endpoint::Endpoint>,
        task: JoinHandle<std::result::Result<(), dhttp::dquic::AcceptError>>,
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
struct HandlerService<H> {
    handler: H,
}

impl<H> Service<dhttp::endpoint::server::UnresolvedRequest> for HandlerService<H>
where
    H: for<'a> Fn(&'a server::Request, &'a server::Response) -> BoxFuture<'a, Result<()>>
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
        Box::pin(async move {
            let (request, response) = dhttp::endpoint::server::resolve(req)
                .await
                .map_err(|error| DhttpError::from_error("server.resolve", error))?;
            let request = server::Request::new(request);
            let response = server::Response::new(response);

            if let Err(error) = handler(&request, &response).await {
                tracing::warn!(error = %error.report(), "dhttp handler failed");
                if let Err(cancel_error) = response.cancel_code(Code::H3_INTERNAL_ERROR).await {
                    tracing::warn!(error = %cancel_error.report(), "failed to cancel response after handler failure");
                }
            } else if let Err(error) = response.finish_if_open().await {
                tracing::warn!(error = %error.report(), "failed to finish response after handler completion");
            }

            request.take().await;
            response.take().await;
            Ok(())
        })
    }
}

pub(crate) fn parse_method(operation: &'static str, method: &str) -> Result<Method> {
    Method::from_bytes(method.as_bytes()).map_err(|error| DhttpError::from_error(operation, error))
}

pub(crate) fn parse_uri(operation: &'static str, uri: &str) -> Result<Uri> {
    uri.parse()
        .map_err(|error| DhttpError::from_error(operation, error))
}

pub(crate) fn parse_status(operation: &'static str, status: u16) -> Result<StatusCode> {
    StatusCode::from_u16(status).map_err(|error| DhttpError::from_error(operation, error))
}

pub(crate) fn parse_header_name(operation: &'static str, name: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|error| DhttpError::from_error(operation, error))
}

pub(crate) fn parse_header_value(operation: &'static str, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| DhttpError::from_error(operation, error))
}

pub(crate) fn parse_headers(
    operation: &'static str,
    headers: Vec<(String, String)>,
) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            parse_header_name(operation, &name)?,
            parse_header_value(operation, &value)?,
        );
    }
    Ok(map)
}

pub(crate) fn header_pairs(
    operation: &'static str,
    headers: &HeaderMap,
) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = value
                .to_str()
                .map_err(|error| DhttpError::from_error(operation, error))?;
            Ok((name.to_string(), value.to_owned()))
        })
        .collect()
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
        async fn panic_task() -> std::result::Result<(), dhttp::dquic::AcceptError> {
            panic!("serve task failed");
        }

        let endpoint = Arc::new(dhttp::endpoint::Endpoint::builder().build().await);
        let handle = ServeHandle::new(endpoint, tokio::spawn(panic_task()));

        assert!(handle.closed().await.is_err());
        handle.closed().await.unwrap();
        assert!(handle.is_finished());
    }

    #[tokio::test]
    async fn serve_handle_abort_suppresses_completed_accept_error() {
        let endpoint = Arc::new(dhttp::endpoint::Endpoint::builder().build().await);
        let (send_complete, recv_complete) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            recv_complete.await.expect("test completion signal");
            Err(dhttp::dquic::AcceptError::ServerUnavailable)
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
