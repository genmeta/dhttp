use crate::{BodyReader, Error, ErrorCode, Result, UploadBody, lifecycle::Scope};
use http_body_util::BodyExt;
use std::{
    future::{Future, IntoFuture},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{RwLock, oneshot},
};

/// Shared SDK handle. Clones share ownership; separately loaded handles do not.
/// Closing one handle leaves the global network and other handles usable.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

pub(crate) struct ClientInner {
    pub endpoint: RwLock<Option<dhttp::Endpoint>>,
    pub scope: Scope,
    pub profile: Option<PathBuf>,
    pub control: tokio::sync::Mutex<()>,
}

impl Client {
    pub fn anonymous() -> Self {
        Self::new(None, None)
    }

    pub async fn load(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self::new(Some(dhttp::Endpoint::load(name).await?), None))
    }

    pub async fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = std::path::absolute(path.as_ref())?;
        Ok(Self::new(
            Some(dhttp::Endpoint::load_from(&path).await?),
            Some(path),
        ))
    }

    pub fn from_endpoint(endpoint: dhttp::Endpoint) -> Self {
        Self::new(Some(endpoint), None)
    }

    fn new(endpoint: Option<dhttp::Endpoint>, profile: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                endpoint: RwLock::new(endpoint),
                scope: Scope::new(),
                profile,
                control: tokio::sync::Mutex::new(()),
            }),
        }
    }

    pub async fn name(&self) -> Option<String> {
        self.inner
            .endpoint
            .read()
            .await
            .as_ref()
            .map(|endpoint| endpoint.name().to_owned())
    }

    pub async fn local_authority(&self) -> Result<Option<dhttp::LocalAuthority>> {
        self.inner.scope.ensure_open()?;
        self.inner
            .endpoint
            .read()
            .await
            .as_ref()
            .map(|endpoint| endpoint.local_authority().map_err(Into::into))
            .transpose()
    }

    /// Apply a successful OCSP replacement only to this SDK handle's clones.
    /// A failed reload leaves its previous endpoint intact.
    pub async fn reload(&self) -> Result<()> {
        let _control = self.inner.control.lock().await;
        self.inner.scope.ensure_open()?;
        let mut endpoint = self.inner.endpoint.write().await;
        let current = endpoint.as_ref().ok_or_else(|| {
            Error::new(ErrorCode::Identity, "anonymous client has no credentials")
        })?;
        let replacement = match &self.inner.profile {
            Some(path) => current.reload_from(path).await?,
            None => current.reload().await?,
        };
        *endpoint = Some(replacement);
        Ok(())
    }

    /// Start connecting now and return a cancellable response future. Callers
    /// can immediately pump UploadWriter without pre-buffering the entire body.
    pub async fn request(
        &self,
        request: http::Request<Option<UploadBody>>,
        options: RequestOptions,
    ) -> Result<ResponseFuture> {
        let operation = self.inner.scope.register()?;
        let endpoint = self.inner.endpoint.read().await.clone();
        let (sender, response) = oneshot::channel();
        let state = operation.state.clone();
        let response_state = state.clone();
        tokio::spawn(async move {
            let deadline = options.timeout;
            let mut sender = Some(sender);
            let result = state
                .run(async {
                    let exchange = exchange(
                        endpoint,
                        request,
                        options,
                        operation.state.clone(),
                        &mut sender,
                    );
                    match deadline {
                        Some(timeout) => {
                            tokio::time::timeout(timeout, exchange).await.map_err(|_| {
                                Error::new(ErrorCode::DeadlineExceeded, "request deadline exceeded")
                            })?
                        }
                        None => exchange.await,
                    }
                })
                .await;
            if let Err(error) = result {
                state.fail(error.clone());
                if let Some(sender) = sender.take() {
                    let _ = sender.send(Err(error));
                }
            }
            drop(operation);
        });
        Ok(ResponseFuture {
            response,
            state: response_state,
            transferred: false,
        })
    }

    /// Cancel all owned exchanges and listeners, waiting until their tasks exit.
    /// There is no implicit request deadline and close cancels without draining.
    pub async fn close(&self) {
        let _control = self.inner.control.lock().await;
        self.inner.scope.close().await;
    }
}

/// SDK send policy. HTTP method, URI, headers, body and extensions remain in
/// the standard http::Request instead of a second message representation.
#[derive(Default)]
pub struct RequestOptions {
    pub expected_remote_owner_hash: Option<dhttp_home::certificate::OwnerHash>,
    /// Total exchange deadline, including upload and response consumption.
    /// None leaves duration under caller control.
    pub timeout: Option<Duration>,
}

/// A standard response. Verified RemoteAuthority remains in its extensions.
pub type ClientResponse = http::Response<BodyReader>;

/// Dropping before response headers cancels the entire exchange.
pub struct ResponseFuture {
    response: oneshot::Receiver<Result<ClientResponse>>,
    state: Arc<crate::lifecycle::OperationState>,
    transferred: bool,
}

impl ResponseFuture {
    /// A separate handle for AbortSignal/task cancellation adapters.
    pub fn cancellation(&self) -> Cancellation {
        Cancellation(self.state.clone())
    }
}

#[derive(Clone)]
pub struct Cancellation(Arc<crate::lifecycle::OperationState>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.fail(Error::cancelled());
    }
}

impl Future for ResponseFuture {
    type Output = Result<ClientResponse>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.response).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(result) => {
                this.transferred = true;
                std::task::Poll::Ready(result.unwrap_or_else(|_| Err(this.state.error())))
            }
        }
    }
}

impl Drop for ResponseFuture {
    fn drop(&mut self) {
        if !self.transferred {
            self.state.fail(Error::cancelled());
        }
    }
}

async fn exchange(
    endpoint: Option<dhttp::Endpoint>,
    message: http::Request<Option<UploadBody>>,
    options: RequestOptions,
    state: Arc<crate::lifecycle::OperationState>,
    sender: &mut Option<oneshot::Sender<Result<ClientResponse>>>,
) -> Result<()> {
    crate::init().await?;
    let (parts, upload) = message.into_parts();
    let message = http::Request::from_parts(parts, dhttp::Empty::new());
    let mut request = match endpoint {
        Some(endpoint) => endpoint.from_request(message),
        None => dhttp::Anonymous.from_request(message),
    };
    if let Some(owner) = options.expected_remote_owner_hash {
        request = request.expect_remote_owner_hash(owner);
    }
    // Uniformly use a fixed native window, including empty requests with trailers.
    let (mut writer, response) = request
        .body(dhttp::WndBuf::new(64 * 1024))
        .into_future()
        .await?;
    let pumping = async move {
        if let Some(mut body) = upload {
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                match frame.into_data() {
                    Ok(bytes) => writer.write_all(&bytes).await?,
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            for (name, value) in trailers.iter() {
                                writer.append_trailer(name.clone(), value.clone())?;
                            }
                        }
                    }
                }
            }
        }
        writer.shutdown().await?;
        Ok(())
    };
    let receiving = async move {
        let response = response.await?;
        let (parts, body) = response.into_parts();
        let (body, reading) = BodyReader::bridge(body, state.clone());
        let response = http::Response::from_parts(parts, body);
        sender
            .take()
            .expect("response headers sent once")
            .send(Ok(response))
            .map_err(|_| Error::cancelled())?;
        reading.await
    };
    // Response headers can arrive while upload is waiting on the language producer.
    // A failure in either direction drops the sibling future and its native handle.
    futures::try_join!(pumping, receiving)?;
    Ok(())
}

impl Default for Client {
    fn default() -> Self {
        Self::anonymous()
    }
}
