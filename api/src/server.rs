use crate::{
    BodyReader, Client, Error, ErrorCode, Result,
    lifecycle::{Operation, Scope},
};
use bytes::Bytes;
use futures::{FutureExt, future::BoxFuture};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::Mutex;

/// Standard request; verified HandshakeSummary remains in its extensions.
pub type ServerRequest = http::Request<BodyReader>;
pub type ServerResponse = http::Response<dhttp::Body>;

type Handler =
    Arc<dyn Fn(ServerRequest) -> BoxFuture<'static, Result<ServerResponse>> + Send + Sync>;

#[derive(Clone)]
struct Service {
    handler: Handler,
    scope: Scope,
}

impl tower_service::Service<http::Request<dhttp::Body>> for Service {
    type Response = ServerResponse;
    type Error = dhttp::BoxError;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(
            self.scope
                .ensure_open()
                .map_err(|error| Box::new(error) as _),
        )
    }
    fn call(&mut self, request: http::Request<dhttp::Body>) -> Self::Future {
        let scope = self.scope.clone();
        let handler = self.handler.clone();
        Box::pin(async move {
            let operation = scope.register()?;
            let reading = scope.register()?;
            let (parts, body) = request.into_parts();
            let (body, worker) = BodyReader::bridge(body, reading.state.clone());
            tokio::spawn(async move {
                let _ = worker.await;
                drop(reading);
            });
            let request = http::Request::from_parts(parts, body);
            // Includes synchronous callback panics and future panics. Neither is
            // exposed to the caller as exception text or allowed to kill the service.
            let handled =
                std::panic::AssertUnwindSafe(async move { handler(request).await }).catch_unwind();
            let response = operation
                .state
                .run(async {
                    Ok(match handled.await {
                        Ok(Ok(response)) => response,
                        failed => {
                            if let Ok(Err(error)) = failed {
                                tracing::warn!(%error, "SDK handler failed");
                            } else {
                                tracing::warn!("SDK handler panicked");
                            }
                            http::Response::builder()
                                .status(500)
                                .body(
                                    Full::new(Bytes::new())
                                        .map_err(|never: Infallible| match never {})
                                        .boxed_unsync(),
                                )
                                .unwrap()
                        }
                    })
                })
                .await?;
            Ok(response.map(|body| OwnedBody::new(body, operation).boxed_unsync()))
        })
    }
}

// Retain handler ownership through response EOF, not just until headers return.
struct OwnedBody {
    body: Option<dhttp::Body>,
    operation: Option<Operation>,
    cancelled: BoxFuture<'static, ()>,
}
impl OwnedBody {
    fn new(body: dhttp::Body, operation: Operation) -> Self {
        let cancelled = operation.state.cancel.clone().cancelled_owned().boxed();
        Self {
            body: Some(body),
            operation: Some(operation),
            cancelled,
        }
    }
}
impl Body for OwnedBody {
    type Data = Bytes;
    type Error = dhttp::BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let Some(body) = &mut this.body else {
            return Poll::Ready(None);
        };
        if this.cancelled.as_mut().poll(cx).is_ready() {
            let error = this.operation.as_ref().unwrap().state.error();
            this.body.take();
            this.operation.take();
            return Poll::Ready(Some(Err(Box::new(error))));
        }
        let result = Pin::new(body).poll_frame(cx);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            this.body.take();
            this.operation.take();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_none()
    }
}

#[derive(Clone)]
pub struct Listener(Arc<ListenerInner>);
struct ListenerInner {
    state: Arc<crate::lifecycle::OperationState>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Listener {
    /// Stop new admission first, then cancel owned handlers and body tasks.
    /// Idempotent; no implicit drain or promise to close shared connections.
    pub async fn close(&self) {
        self.0
            .state
            .fail(Error::new(ErrorCode::Closed, "listener closed"));
        let mut task = self.0.task.lock().await;
        if let Some(task) = task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for ListenerInner {
    fn drop(&mut self) {
        self.state
            .fail(Error::new(ErrorCode::Closed, "listener dropped"));
    }
}

impl Client {
    /// Register a named endpoint's service. Anonymous handles cannot listen.
    /// Default discovery/publication will be layered here in the next stage.
    pub async fn listen<F, Fut>(&self, scopes: dhttp::Scopes, handler: F) -> Result<Listener>
    where
        F: Fn(ServerRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ServerResponse>> + Send + 'static,
    {
        let _control = self.inner.control.lock().await;
        let operation = self.inner.scope.register()?;
        let endpoint = self
            .inner
            .endpoint
            .read()
            .await
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::Identity, "anonymous client cannot listen"))?;
        let state = operation.state.clone();
        let scope = Scope::new();
        let listening = state
            .run(async {
                crate::init().await?;
                endpoint
                    .listen(
                        scopes,
                        Service {
                            handler: Arc::new(move |request| Box::pin(handler(request))),
                            scope: scope.clone(),
                        },
                    )
                    .await
                    .map_err(Into::into)
            })
            .await?;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            task_state.cancel.cancelled().await;
            drop(listening);
            scope.close().await;
            drop(operation);
        });
        Ok(Listener(Arc::new(ListenerInner {
            state,
            task: Mutex::new(Some(task)),
        })))
    }
}

#[cfg(test)]
#[path = "../tests/unit/server.rs"]
mod tests;
