use std::sync::{Arc, LazyLock, Mutex};

use ::napi::{
    Env, Error, Status,
    bindgen_prelude::{
        Buffer, Either, FnArgs, Function, Promise, PromiseRaw, Result as NapiResult,
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

type ServerHandlerArgs = FnArgs<(ServerRequest, ServerResponse)>;
type ServerHandlerResult = Either<Promise<()>, ()>;

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

#[napi(js_name = "Home")]
pub struct Home {
    inner: crate::home::Home,
}

#[napi]
impl Home {
    #[napi(constructor)]
    pub fn new(path: String) -> Self {
        Self {
            inner: crate::home::Home::from_path(path),
        }
    }

    #[napi]
    pub fn load() -> NapiResult<Home> {
        crate::home::Home::load()
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[napi]
    pub fn identity_home(&self, name: String) -> NapiResult<IdentityHome> {
        self.inner
            .identity_home(&name)
            .map(|inner| IdentityHome { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load_identity(&self, name: String) -> NapiResult<IdentityHome> {
        self.inner
            .load_identity(&name)
            .await
            .map(|inner| IdentityHome { inner })
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

#[napi(js_name = "IdentityHome")]
pub struct IdentityHome {
    inner: crate::home::IdentityHome,
}

#[napi]
impl IdentityHome {
    #[napi]
    pub fn from_path(path: String) -> NapiResult<IdentityHome> {
        crate::home::IdentityHome::from_path(path)
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

#[napi(js_name = "ClientRequest")]
pub struct ClientRequest {
    inner: Arc<Mutex<Option<crate::endpoint::client::Request>>>,
}

impl Drop for ClientRequest {
    fn drop(&mut self) {
        let request = match self.inner.lock() {
            Ok(mut request) => request.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(request) = request {
            drop_with_napi_runtime(request);
        }
    }
}

impl From<crate::endpoint::client::Request> for ClientRequest {
    fn from(inner: crate::endpoint::client::Request) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl ClientRequest {
    #[napi]
    pub fn method(&self, method: String) -> NapiResult<()> {
        self.set_method(method)
    }

    #[napi]
    pub fn uri(&self, uri: String) -> NapiResult<()> {
        self.set_uri(uri)
    }

    #[napi]
    pub fn header(&self, name: String, value: String) -> NapiResult<()> {
        self.set_header(name, value)
    }

    #[napi]
    pub fn headers(&self, headers: Vec<(String, String)>) -> NapiResult<()> {
        self.set_headers(headers)
    }

    #[napi]
    pub fn body(&self, content: Buffer) -> NapiResult<()> {
        self.set_body(content)
    }

    #[napi]
    pub fn trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.set_trailer(name, value)
    }

    #[napi]
    pub fn trailers(&self, trailers: Vec<(String, String)>) -> NapiResult<()> {
        self.set_trailers(trailers)
    }

    #[napi]
    pub fn set_method(&self, method: String) -> NapiResult<()> {
        self.with_ref("client_request.set_method", |request| {
            request.set_method(&method)
        })
    }

    #[napi]
    pub fn set_uri(&self, uri: String) -> NapiResult<()> {
        self.with_ref("client_request.set_uri", |request| request.set_uri(&uri))
    }

    #[napi]
    pub fn set_header(&self, name: String, value: String) -> NapiResult<()> {
        self.with_ref("client_request.set_header", |request| {
            request.set_header(&name, &value)
        })
    }

    #[napi]
    pub fn set_headers(&self, headers: Vec<(String, String)>) -> NapiResult<()> {
        self.with_ref("client_request.set_headers", |request| {
            request.set_headers(headers)
        })
    }

    #[napi]
    pub fn set_body(&self, content: Buffer) -> NapiResult<()> {
        self.with_ref("client_request.set_body", |request| {
            request.set_body(content.to_vec());
            Ok(())
        })
    }

    #[napi]
    pub fn set_trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.with_ref("client_request.set_trailer", |request| {
            request.set_trailer(&name, &value)
        })
    }

    #[napi]
    pub fn set_trailers(&self, trailers: Vec<(String, String)>) -> NapiResult<()> {
        self.with_ref("client_request.set_trailers", |request| {
            request.set_trailers(trailers)
        })
    }

    #[napi]
    pub fn write<'env>(&self, env: &'env Env, content: Buffer) -> NapiResult<PromiseRaw<'env, ()>> {
        let content = content.to_vec();
        let request = self
            .shared_request("client_request.write")
            .map_err(napi_error)?;
        env.spawn_future(async move { request.write(content).await.map_err(napi_error) })
    }

    #[napi]
    pub async fn flush(&self) -> NapiResult<()> {
        let request = self
            .shared_request("client_request.flush")
            .map_err(napi_error)?;
        request.flush().await.map_err(napi_error)
    }

    #[napi]
    pub async fn close(&self) -> NapiResult<()> {
        let request = self
            .shared_request("client_request.close")
            .map_err(napi_error)?;
        request.close().await.map_err(napi_error)
    }

    #[napi]
    pub async fn cancel(&self, code: u32) -> NapiResult<()> {
        let request = self
            .shared_request("client_request.cancel")
            .map_err(napi_error)?;
        request.cancel(u64::from(code)).await.map_err(napi_error)
    }

    #[napi]
    pub async fn response(&self) -> NapiResult<ClientResponse> {
        let request = self
            .shared_request("client_request.response")
            .map_err(napi_error)?;
        request
            .response()
            .await
            .map(ClientResponse::from)
            .map_err(napi_error)
    }

    #[napi]
    pub async fn into_response(&self) -> NapiResult<ClientResponse> {
        let request = self
            .inner
            .lock()
            .map_err(|_| {
                napi_error(crate::error::DhttpError::from_message(
                    "client_request.into_response",
                    "request mutex is poisoned",
                ))
            })?
            .take()
            .ok_or_else(|| {
                napi_error(crate::error::DhttpError::from_message(
                    "client_request.into_response",
                    "request is closed",
                ))
            })?;
        request
            .into_response()
            .await
            .map(ClientResponse::from)
            .map_err(napi_error)
    }

    fn with_ref<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&crate::endpoint::client::Request) -> crate::endpoint::Result<T>,
    ) -> NapiResult<T> {
        let guard = self.inner.lock().map_err(|_| {
            napi_error(crate::error::DhttpError::from_message(
                operation,
                "request mutex is poisoned",
            ))
        })?;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                operation,
                "request is closed",
            ))
        })?;
        f(request).map_err(napi_error)
    }

    fn shared_request(
        &self,
        operation: &'static str,
    ) -> crate::endpoint::Result<crate::endpoint::client::Request> {
        let guard = self.inner.lock().map_err(|_| {
            crate::error::DhttpError::from_message(operation, "request mutex is poisoned")
        })?;
        let request = guard.as_ref().ok_or_else(|| {
            crate::error::DhttpError::from_message(operation, "request is closed")
        })?;
        Ok(request.shared_handle())
    }
}

#[napi(js_name = "ClientResponse")]
pub struct ClientResponse {
    inner: crate::endpoint::client::Response,
}

impl From<crate::endpoint::client::Response> for ClientResponse {
    fn from(inner: crate::endpoint::client::Response) -> Self {
        Self { inner }
    }
}

#[napi]
impl ClientResponse {
    #[napi]
    pub async fn next_response(&self) -> NapiResult<()> {
        self.inner.next_response().await.map_err(napi_error)
    }

    #[napi]
    pub fn status(&self) -> NapiResult<u16> {
        self.inner.status().map_err(napi_error)
    }

    #[napi]
    pub fn headers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.headers().map_err(napi_error)
    }

    #[napi]
    pub fn header(&self, name: String) -> NapiResult<Option<String>> {
        self.inner.header(&name).map_err(napi_error)
    }

    #[napi]
    pub async fn read(&self) -> NapiResult<Option<Vec<u8>>> {
        self.inner.read().await.map_err(napi_error)
    }

    #[napi]
    pub async fn read_to_bytes(&self) -> NapiResult<Vec<u8>> {
        self.inner.read_to_bytes().await.map_err(napi_error)
    }

    #[napi]
    pub async fn read_to_string(&self) -> NapiResult<String> {
        self.inner.read_to_string().await.map_err(napi_error)
    }

    #[napi]
    pub async fn trailers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.trailers().await.map_err(napi_error)
    }

    #[napi]
    pub async fn stop(&self, code: u32) -> NapiResult<()> {
        self.inner.stop(u64::from(code)).await.map_err(napi_error)
    }

    #[napi]
    pub fn agent_name(&self) -> NapiResult<String> {
        self.inner.agent_name().map_err(napi_error)
    }
}

#[napi(js_name = "ServerRequest")]
pub struct ServerRequest {
    inner: crate::endpoint::server::Request,
}

impl From<&crate::endpoint::server::Request> for ServerRequest {
    fn from(inner: &crate::endpoint::server::Request) -> Self {
        Self {
            inner: inner.shared_handle(),
        }
    }
}

#[napi]
impl ServerRequest {
    #[napi]
    pub fn method(&self) -> NapiResult<String> {
        self.inner.method().map_err(napi_error)
    }

    #[napi]
    pub fn uri(&self) -> NapiResult<String> {
        self.inner.uri().map_err(napi_error)
    }

    #[napi]
    pub fn scheme(&self) -> NapiResult<Option<String>> {
        self.inner.scheme().map_err(napi_error)
    }

    #[napi]
    pub fn authority(&self) -> NapiResult<Option<String>> {
        self.inner.authority().map_err(napi_error)
    }

    #[napi]
    pub fn path(&self) -> NapiResult<Option<String>> {
        self.inner.path().map_err(napi_error)
    }

    #[napi]
    pub fn protocol(&self) -> NapiResult<Option<String>> {
        self.inner.protocol().map_err(napi_error)
    }

    #[napi]
    pub fn headers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.headers().map_err(napi_error)
    }

    #[napi]
    pub fn header(&self, name: String) -> NapiResult<Option<String>> {
        self.inner.header(&name).map_err(napi_error)
    }

    #[napi]
    pub async fn read(&self) -> NapiResult<Option<Vec<u8>>> {
        self.inner.read().await.map_err(napi_error)
    }

    #[napi]
    pub async fn read_to_bytes(&self) -> NapiResult<Vec<u8>> {
        self.inner.read_to_bytes().await.map_err(napi_error)
    }

    #[napi]
    pub async fn read_to_string(&self) -> NapiResult<String> {
        self.inner.read_to_string().await.map_err(napi_error)
    }

    #[napi]
    pub async fn trailers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.trailers().await.map_err(napi_error)
    }

    #[napi]
    pub async fn stop(&self, code: u32) -> NapiResult<()> {
        self.inner.stop(u64::from(code)).await.map_err(napi_error)
    }

    #[napi]
    pub fn agent_name(&self) -> NapiResult<Option<String>> {
        self.inner.agent_name().map_err(napi_error)
    }

    #[napi]
    pub fn stream_id(&self) -> NapiResult<i64> {
        self.inner
            .stream_id()
            .and_then(|stream_id| {
                i64::try_from(stream_id).map_err(|error| {
                    crate::error::DhttpError::from_error("server_request.stream_id", error)
                })
            })
            .map_err(napi_error)
    }
}

#[napi(js_name = "ServerResponse")]
pub struct ServerResponse {
    inner: crate::endpoint::server::Response,
}

impl From<&crate::endpoint::server::Response> for ServerResponse {
    fn from(inner: &crate::endpoint::server::Response) -> Self {
        Self {
            inner: inner.shared_handle(),
        }
    }
}

#[napi]
impl ServerResponse {
    #[napi]
    pub fn status(&self) -> NapiResult<Option<u16>> {
        self.inner.status().map_err(napi_error)
    }

    #[napi]
    pub fn set_status(&self, status: u16) -> NapiResult<()> {
        self.inner.set_status(status).map_err(napi_error)
    }

    #[napi]
    pub fn headers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.headers().map_err(napi_error)
    }

    #[napi]
    pub fn set_header(&self, name: String, value: String) -> NapiResult<()> {
        self.inner.set_header(&name, &value).map_err(napi_error)
    }

    #[napi]
    pub fn set_body(&self, content: Buffer) -> NapiResult<()> {
        self.inner.set_body(content.to_vec()).map_err(napi_error)
    }

    #[napi]
    pub fn write<'env>(&self, env: &'env Env, content: Buffer) -> NapiResult<PromiseRaw<'env, ()>> {
        let content = content.to_vec();
        let response = self.inner.shared_handle();
        env.spawn_future(async move { response.write(content).await.map_err(napi_error) })
    }

    #[napi]
    pub async fn flush(&self) -> NapiResult<()> {
        self.inner.flush().await.map_err(napi_error)
    }

    #[napi]
    pub fn trailers(&self) -> NapiResult<Vec<(String, String)>> {
        self.inner.trailers().map_err(napi_error)
    }

    #[napi]
    pub fn set_trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.inner.set_trailer(&name, &value).map_err(napi_error)
    }

    #[napi]
    pub fn set_trailers(&self, trailers: Vec<(String, String)>) -> NapiResult<()> {
        self.inner.set_trailers(trailers).map_err(napi_error)
    }

    #[napi]
    pub async fn close(&self) -> NapiResult<()> {
        self.inner.close().await.map_err(napi_error)
    }

    #[napi]
    pub async fn cancel(&self, code: u32) -> NapiResult<()> {
        self.inner.cancel(u64::from(code)).await.map_err(napi_error)
    }

    #[napi]
    pub fn agent_name(&self) -> NapiResult<String> {
        self.inner.agent_name().map_err(napi_error)
    }

    #[napi]
    pub fn stream_id(&self) -> NapiResult<i64> {
        self.inner
            .stream_id()
            .and_then(|stream_id| {
                i64::try_from(stream_id).map_err(|error| {
                    crate::error::DhttpError::from_error("server_response.stream_id", error)
                })
            })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn finish(&self) -> NapiResult<()> {
        self.inner.finish().await.map_err(napi_error)
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
    fn inner(&self) -> &crate::endpoint::ServeHandle {
        self.inner.as_ref().expect("serve handle is closed")
    }
}

#[napi]
impl ServeHandle {
    #[napi]
    pub async fn shutdown(&self) -> NapiResult<()> {
        self.inner().shutdown().await.map_err(napi_error)
    }

    #[napi]
    pub fn abort(&self) {
        self.inner().abort();
    }

    #[napi]
    pub fn is_finished(&self) -> bool {
        self.inner().is_finished()
    }

    #[napi]
    pub async fn closed(&self) -> NapiResult<()> {
        self.inner().closed().await.map_err(napi_error)
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
    fn inner(&self) -> &crate::endpoint::Endpoint {
        self.inner.as_ref().expect("endpoint is closed")
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
        self.inner().identity().map(Identity::from)
    }

    #[napi]
    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner().bind_patterns()
    }

    #[napi]
    pub fn request(&self) -> ClientRequest {
        self.inner().request().into()
    }

    #[napi]
    pub fn get(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .get(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn post(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .post(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn put(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .put(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .delete(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn patch(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .patch(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn head(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .head(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn options(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .options(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn trace(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner()
            .trace(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn serve(
        &self,
        handler: Function<ServerHandlerArgs, ServerHandlerResult>,
    ) -> NapiResult<ServeHandle> {
        let handler = handler
            .build_threadsafe_function::<ServerHandlerArgs>()
            .callee_handled::<false>()
            .build()?;
        let handler = Arc::new(handler);
        let inner = within_runtime_if_available(|| {
            self.inner().serve(move |request, response| {
                let handler = handler.clone();
                let request = ServerRequest::from(request);
                let response = ServerResponse::from(response);
                Box::pin(async move {
                    let result = handler
                        .call_async_catch((request, response).into())
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
