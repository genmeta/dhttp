use std::sync::Arc;

use ::pyo3::{exceptions::PyRuntimeError, prelude::*};
use futures::{FutureExt, future::BoxFuture};
use tokio::sync::Mutex;

fn py_error(error: crate::error::DhttpError) -> PyErr {
    PyRuntimeError::new_err(error.report().to_owned())
}

fn dhttp_py_error(operation: &'static str, error: PyErr) -> crate::error::DhttpError {
    crate::error::DhttpError::from_error(operation, error)
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
}

#[pyclass(name = "Home")]
pub struct Home {
    inner: crate::home::Home,
}

#[pymethods]
impl Home {
    #[new]
    pub fn new(path: String) -> Self {
        Self {
            inner: crate::home::Home::from_path(path),
        }
    }

    #[staticmethod]
    pub fn load() -> PyResult<Self> {
        crate::home::Home::load()
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    pub fn identity_home(&self, name: String) -> PyResult<IdentityHome> {
        self.inner
            .identity_home(&name)
            .map(|inner| IdentityHome { inner })
            .map_err(py_error)
    }

    pub async fn load_identity(&self, name: String) -> PyResult<IdentityHome> {
        self.inner
            .load_identity(&name)
            .await
            .map(|inner| IdentityHome { inner })
            .map_err(py_error)
    }

    pub async fn identity_exists(&self, name: String) -> PyResult<bool> {
        self.inner.identity_exists(&name).await.map_err(py_error)
    }

    pub async fn identities(&self) -> PyResult<Vec<String>> {
        self.inner.identities().await.map_err(py_error)
    }
}

#[pyclass(name = "IdentityHome")]
pub struct IdentityHome {
    inner: crate::home::IdentityHome,
}

#[pymethods]
impl IdentityHome {
    #[new]
    pub fn new(path: String) -> PyResult<Self> {
        crate::home::IdentityHome::from_path(path)
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    pub fn name(&self) -> String {
        self.inner.name()
    }

    pub fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    pub async fn identity(&self) -> PyResult<Identity> {
        self.inner
            .identity()
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

#[pyclass(name = "ClientRequest")]
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

#[pymethods]
impl ClientRequest {
    pub fn method(&self, method: String) -> PyResult<()> {
        self.set_method(method)
    }

    pub fn uri(&self, uri: String) -> PyResult<()> {
        self.set_uri(uri)
    }

    pub fn header(&self, name: String, value: String) -> PyResult<()> {
        self.set_header(name, value)
    }

    pub fn body(&self, content: Vec<u8>) -> PyResult<()> {
        self.set_body(content)
    }

    pub fn trailer(&self, name: String, value: String) -> PyResult<()> {
        self.set_trailer(name, value)
    }

    pub fn set_method(&self, method: String) -> PyResult<()> {
        self.with_ref("client_request.set_method", |request| {
            request.set_method(&method)
        })
    }

    pub fn set_uri(&self, uri: String) -> PyResult<()> {
        self.with_ref("client_request.set_uri", |request| request.set_uri(&uri))
    }

    pub fn set_header(&self, name: String, value: String) -> PyResult<()> {
        self.with_ref("client_request.set_header", |request| {
            request.set_header(&name, &value)
        })
    }

    pub fn set_body(&self, content: Vec<u8>) -> PyResult<()> {
        self.with_ref("client_request.set_body", |request| {
            request.set_body(content);
            Ok(())
        })
    }

    pub fn set_trailer(&self, name: String, value: String) -> PyResult<()> {
        self.with_ref("client_request.set_trailer", |request| {
            request.set_trailer(&name, &value)
        })
    }

    pub async fn write(&self, content: Vec<u8>) -> PyResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.write",
                "request is closed",
            ))
        })?;
        request.write(content).await.map_err(py_error)
    }

    pub async fn flush(&self) -> PyResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.flush",
                "request is closed",
            ))
        })?;
        request.flush().await.map_err(py_error)
    }

    pub async fn close(&self) -> PyResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.close",
                "request is closed",
            ))
        })?;
        request.close().await.map_err(py_error)
    }

    pub async fn cancel(&self, code: u64) -> PyResult<()> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.cancel",
                "request is closed",
            ))
        })?;
        request.cancel(code).await.map_err(py_error)
    }

    pub async fn response(&self) -> PyResult<ClientResponse> {
        let guard = self.inner.lock().await;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.response",
                "request is closed",
            ))
        })?;
        request
            .response()
            .await
            .map(ClientResponse::from)
            .map_err(py_error)
    }

    pub async fn into_response(&self) -> PyResult<ClientResponse> {
        let request = self.inner.lock().await.take().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                "client_request.into_response",
                "request is closed",
            ))
        })?;
        request
            .into_response()
            .await
            .map(ClientResponse::from)
            .map_err(py_error)
    }
}

impl ClientRequest {
    fn with_ref<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&crate::endpoint::client::Request) -> crate::endpoint::Result<T>,
    ) -> PyResult<T> {
        let guard = self.inner.try_lock().map_err(|_| {
            py_error(crate::error::DhttpError::from_message(
                operation,
                "request is busy",
            ))
        })?;
        let request = guard.as_ref().ok_or_else(|| {
            py_error(crate::error::DhttpError::from_message(
                operation,
                "request is closed",
            ))
        })?;
        f(request).map_err(py_error)
    }
}

#[pyclass(name = "ClientResponse")]
pub struct ClientResponse {
    inner: crate::endpoint::client::Response,
}

impl From<crate::endpoint::client::Response> for ClientResponse {
    fn from(inner: crate::endpoint::client::Response) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ClientResponse {
    pub async fn next_response(&self) -> PyResult<()> {
        self.inner.next_response().await.map_err(py_error)
    }

    pub fn status(&self) -> PyResult<u16> {
        self.inner.status().map_err(py_error)
    }

    pub fn headers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.headers().map_err(py_error)
    }

    pub fn header(&self, name: String) -> PyResult<Option<String>> {
        self.inner.header(&name).map_err(py_error)
    }

    pub async fn read(&self) -> PyResult<Option<Vec<u8>>> {
        self.inner.read().await.map_err(py_error)
    }

    pub async fn read_to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.read_to_bytes().await.map_err(py_error)
    }

    pub async fn read_to_string(&self) -> PyResult<String> {
        self.inner.read_to_string().await.map_err(py_error)
    }

    pub async fn trailers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.trailers().await.map_err(py_error)
    }

    pub async fn stop(&self, code: u64) -> PyResult<()> {
        self.inner.stop(code).await.map_err(py_error)
    }

    pub fn agent_name(&self) -> PyResult<String> {
        self.inner.agent_name().map_err(py_error)
    }
}

#[pyclass(name = "ServerRequest")]
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

#[pymethods]
impl ServerRequest {
    pub fn method(&self) -> PyResult<String> {
        self.inner.method().map_err(py_error)
    }

    pub fn uri(&self) -> PyResult<String> {
        self.inner.uri().map_err(py_error)
    }

    pub fn scheme(&self) -> PyResult<Option<String>> {
        self.inner.scheme().map_err(py_error)
    }

    pub fn authority(&self) -> PyResult<Option<String>> {
        self.inner.authority().map_err(py_error)
    }

    pub fn path(&self) -> PyResult<Option<String>> {
        self.inner.path().map_err(py_error)
    }

    pub fn protocol(&self) -> PyResult<Option<String>> {
        self.inner.protocol().map_err(py_error)
    }

    pub fn headers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.headers().map_err(py_error)
    }

    pub fn header(&self, name: String) -> PyResult<Option<String>> {
        self.inner.header(&name).map_err(py_error)
    }

    pub async fn read(&self) -> PyResult<Option<Vec<u8>>> {
        self.inner.read().await.map_err(py_error)
    }

    pub async fn read_to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.read_to_bytes().await.map_err(py_error)
    }

    pub async fn read_to_string(&self) -> PyResult<String> {
        self.inner.read_to_string().await.map_err(py_error)
    }

    pub async fn trailers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.trailers().await.map_err(py_error)
    }

    pub async fn stop(&self, code: u64) -> PyResult<()> {
        self.inner.stop(code).await.map_err(py_error)
    }

    pub fn agent_name(&self) -> PyResult<Option<String>> {
        self.inner.agent_name().map_err(py_error)
    }

    pub fn stream_id(&self) -> PyResult<u64> {
        self.inner.stream_id().map_err(py_error)
    }
}

#[pyclass(name = "ServerResponse")]
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

#[pymethods]
impl ServerResponse {
    pub fn status(&self) -> PyResult<Option<u16>> {
        self.inner.status().map_err(py_error)
    }

    pub fn set_status(&self, status: u16) -> PyResult<()> {
        self.inner.set_status(status).map_err(py_error)
    }

    pub fn headers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.headers().map_err(py_error)
    }

    pub fn set_header(&self, name: String, value: String) -> PyResult<()> {
        self.inner.set_header(&name, &value).map_err(py_error)
    }

    pub fn set_body(&self, content: Vec<u8>) -> PyResult<()> {
        self.inner.set_body(content).map_err(py_error)
    }

    pub async fn write(&self, content: Vec<u8>) -> PyResult<()> {
        self.inner.write(content).await.map_err(py_error)
    }

    pub async fn flush(&self) -> PyResult<()> {
        self.inner.flush().await.map_err(py_error)
    }

    pub fn trailers(&self) -> PyResult<Vec<(String, String)>> {
        self.inner.trailers().map_err(py_error)
    }

    pub fn set_trailer(&self, name: String, value: String) -> PyResult<()> {
        self.inner.set_trailer(&name, &value).map_err(py_error)
    }

    pub fn set_trailers(&self, trailers: Vec<(String, String)>) -> PyResult<()> {
        self.inner.set_trailers(trailers).map_err(py_error)
    }

    pub async fn close(&self) -> PyResult<()> {
        self.inner.close().await.map_err(py_error)
    }

    pub async fn cancel(&self, code: u64) -> PyResult<()> {
        self.inner.cancel(code).await.map_err(py_error)
    }

    pub fn agent_name(&self) -> PyResult<String> {
        self.inner.agent_name().map_err(py_error)
    }

    pub fn stream_id(&self) -> PyResult<u64> {
        self.inner.stream_id().map_err(py_error)
    }

    pub async fn finish(&self) -> PyResult<()> {
        self.inner.finish().await.map_err(py_error)
    }
}

#[pyclass(name = "ServeHandle")]
pub struct ServeHandle {
    inner: crate::endpoint::ServeHandle,
}

#[pymethods]
impl ServeHandle {
    pub async fn shutdown(&self) -> PyResult<()> {
        self.inner.shutdown().await.map_err(py_error)
    }

    pub fn abort(&self) {
        self.inner.abort();
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    pub async fn closed(&self) -> PyResult<()> {
        self.inner.closed().await.map_err(py_error)
    }
}

#[pyclass(name = "Endpoint")]
pub struct Endpoint {
    inner: crate::endpoint::Endpoint,
}

#[pymethods]
impl Endpoint {
    #[staticmethod]
    pub async fn create(options: Option<&EndpointOptions>) -> PyResult<Self> {
        let options = options.map(|options| options.inner.clone());
        crate::endpoint::Endpoint::create(options)
            .await
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    #[staticmethod]
    pub async fn load(name: String) -> PyResult<Self> {
        crate::endpoint::Endpoint::load(&name)
            .await
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    #[staticmethod]
    pub async fn load_from(path: String) -> PyResult<Self> {
        crate::endpoint::Endpoint::load_from(path)
            .await
            .map(|inner| Self { inner })
            .map_err(py_error)
    }

    pub fn identity(&self) -> Option<Identity> {
        self.inner.identity().map(Identity::from)
    }

    pub fn bind_patterns(&self) -> Vec<String> {
        self.inner.bind_patterns()
    }

    pub fn request(&self) -> ClientRequest {
        self.inner.request().into()
    }

    pub fn get(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .get(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn post(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .post(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn put(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .put(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn delete(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .delete(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn patch(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .patch(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn head(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .head(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn options(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .options(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn trace(&self, uri: String) -> PyResult<ClientRequest> {
        self.inner
            .trace(&uri)
            .map(ClientRequest::from)
            .map_err(py_error)
    }

    pub fn serve(&self, handler: Py<PyAny>) -> PyResult<ServeHandle> {
        let locals = Python::attach(|py| pyo3_async_runtimes::tokio::get_current_locals(py).ok());
        let handler = Arc::new(handler);
        let inner = self.inner.serve(move |request, response| {
            let handler = handler.clone();
            let locals = locals.clone();
            let request = ServerRequest::from(request);
            let response = ServerResponse::from(response);
            Box::pin(async move {
                let future = Python::attach(
                    |py| -> PyResult<Option<BoxFuture<'static, PyResult<Py<PyAny>>>>> {
                        let request = Py::new(py, request)?;
                        let response = Py::new(py, response)?;
                        let result = handler.as_ref().call1(py, (request, response))?;
                        let is_awaitable = py
                            .import("inspect")?
                            .call_method1("isawaitable", (result.bind(py),))?
                            .extract()?;
                        if is_awaitable {
                            let locals = locals.as_ref().ok_or_else(|| {
                                PyRuntimeError::new_err(
                                    "async dhttp handler requires a running asyncio task",
                                )
                            })?;
                            let future = pyo3_async_runtimes::into_future_with_locals(
                                locals,
                                result.into_bound(py),
                            )?;
                            Ok(Some(future.boxed()))
                        } else {
                            Ok(None)
                        }
                    },
                )
                .map_err(|error| dhttp_py_error("pyo3.handler", error))?;
                if let Some(future) = future {
                    future
                        .await
                        .map_err(|error| dhttp_py_error("pyo3.handler", error))?;
                }
                Ok(())
            })
        });
        Ok(ServeHandle { inner })
    }
}

#[pymodule]
pub fn dhttp_api(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Identity>()?;
    module.add_class::<Home>()?;
    module.add_class::<IdentityHome>()?;
    module.add_class::<EndpointOptions>()?;
    module.add_class::<ClientRequest>()?;
    module.add_class::<ClientResponse>()?;
    module.add_class::<ServerRequest>()?;
    module.add_class::<ServerResponse>()?;
    module.add_class::<ServeHandle>()?;
    module.add_class::<Endpoint>()?;
    Ok(())
}
