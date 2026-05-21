use ::pyo3::{exceptions::PyRuntimeError, prelude::*};

fn py_error(error: crate::error::DhttpError) -> PyErr {
    PyRuntimeError::new_err(error.report().to_owned())
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
    fn name(&self) -> String {
        self.inner.name()
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
    inner: crate::endpoint::client::Request,
}

impl From<crate::endpoint::client::Request> for ClientRequest {
    fn from(inner: crate::endpoint::client::Request) -> Self {
        Self { inner }
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

    pub fn body(&self, content: Vec<u8>) {
        self.set_body(content);
    }

    pub fn trailer(&self, name: String, value: String) -> PyResult<()> {
        self.set_trailer(name, value)
    }

    pub fn set_method(&self, method: String) -> PyResult<()> {
        self.inner.set_method(&method).map_err(py_error)
    }

    pub fn set_uri(&self, uri: String) -> PyResult<()> {
        self.inner.set_uri(&uri).map_err(py_error)
    }

    pub fn set_header(&self, name: String, value: String) -> PyResult<()> {
        self.inner.set_header(&name, &value).map_err(py_error)
    }

    pub fn set_body(&self, content: Vec<u8>) {
        self.inner.set_body(content);
    }

    pub fn set_trailer(&self, name: String, value: String) -> PyResult<()> {
        self.inner.set_trailer(&name, &value).map_err(py_error)
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
}

#[pymodule]
pub fn dhttp_api(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Identity>()?;
    module.add_class::<Home>()?;
    module.add_class::<EndpointOptions>()?;
    module.add_class::<ClientRequest>()?;
    module.add_class::<Endpoint>()?;
    Ok(())
}
