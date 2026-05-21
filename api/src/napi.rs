use std::sync::Arc;

use ::napi::{Error, Status, bindgen_prelude::Result as NapiResult};
use napi_derive::napi;
use tokio::sync::Mutex;

fn napi_error(error: crate::error::DhttpError) -> Error {
    Error::new(Status::GenericFailure, error.report().to_owned())
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
    pub fn body(&self, content: Vec<u8>) -> NapiResult<()> {
        self.set_body(content)
    }

    #[napi]
    pub fn trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.set_trailer(name, value)
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
    pub fn set_body(&self, content: Vec<u8>) -> NapiResult<()> {
        self.with_ref("client_request.set_body", |request| {
            request.set_body(content);
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
    pub async fn write(&self, content: Vec<u8>) -> NapiResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                "client_request.write",
                "request is closed",
            ))
        })?;
        request.write(content).await.map_err(napi_error)
    }

    #[napi]
    pub async fn flush(&self) -> NapiResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                "client_request.flush",
                "request is closed",
            ))
        })?;
        request.flush().await.map_err(napi_error)
    }

    #[napi]
    pub async fn close(&self) -> NapiResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                "client_request.close",
                "request is closed",
            ))
        })?;
        request.close().await.map_err(napi_error)
    }

    #[napi]
    pub async fn cancel(&self, code: u32) -> NapiResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                "client_request.cancel",
                "request is closed",
            ))
        })?;
        request.cancel(u64::from(code)).await.map_err(napi_error)
    }

    #[napi]
    pub async fn response(&self) -> NapiResult<ClientResponse> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            napi_error(crate::error::DhttpError::from_message(
                "client_request.response",
                "request is closed",
            ))
        })?;
        request
            .response()
            .await
            .map(ClientResponse::from)
            .map_err(napi_error)
    }

    #[napi]
    pub async fn into_response(&self) -> NapiResult<ClientResponse> {
        let request = self.inner.lock().await.take().ok_or_else(|| {
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
        let guard = self.inner.try_lock().map_err(|_| {
            napi_error(crate::error::DhttpError::from_message(
                operation,
                "request is busy",
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

#[napi(js_name = "Endpoint")]
pub struct Endpoint {
    inner: crate::endpoint::Endpoint,
}

#[napi]
impl Endpoint {
    #[napi]
    pub async fn create(options: Option<&EndpointOptions>) -> NapiResult<Endpoint> {
        let options = options.map(|options| options.inner.clone());
        crate::endpoint::Endpoint::create(options)
            .await
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load(name: String) -> NapiResult<Endpoint> {
        crate::endpoint::Endpoint::load(&name)
            .await
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub async fn load_from(path: String) -> NapiResult<Endpoint> {
        crate::endpoint::Endpoint::load_from(path)
            .await
            .map(|inner| Self { inner })
            .map_err(napi_error)
    }

    #[napi]
    pub fn identity(&self) -> Option<Identity> {
        self.inner.identity().map(Identity::from)
    }

    #[napi]
    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner.bind_patterns()
    }

    #[napi]
    pub fn request(&self) -> ClientRequest {
        self.inner.request().into()
    }

    #[napi]
    pub fn get(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .get(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn post(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .post(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn put(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .put(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn delete(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .delete(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn patch(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .patch(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn head(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .head(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn options(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .options(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }

    #[napi]
    pub fn trace(&self, uri: String) -> NapiResult<ClientRequest> {
        self.inner
            .trace(&uri)
            .map(ClientRequest::from)
            .map_err(napi_error)
    }
}
