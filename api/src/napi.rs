use ::napi::{Error, Status, bindgen_prelude::Result as NapiResult};
use napi_derive::napi;

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
    inner: crate::endpoint::client::Request,
}

impl From<crate::endpoint::client::Request> for ClientRequest {
    fn from(inner: crate::endpoint::client::Request) -> Self {
        Self { inner }
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
    pub fn body(&self, content: Vec<u8>) {
        self.set_body(content);
    }

    #[napi]
    pub fn trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.set_trailer(name, value)
    }

    #[napi]
    pub fn set_method(&self, method: String) -> NapiResult<()> {
        self.inner.set_method(&method).map_err(napi_error)
    }

    #[napi]
    pub fn set_uri(&self, uri: String) -> NapiResult<()> {
        self.inner.set_uri(&uri).map_err(napi_error)
    }

    #[napi]
    pub fn set_header(&self, name: String, value: String) -> NapiResult<()> {
        self.inner.set_header(&name, &value).map_err(napi_error)
    }

    #[napi]
    pub fn set_body(&self, content: Vec<u8>) {
        self.inner.set_body(content);
    }

    #[napi]
    pub fn set_trailer(&self, name: String, value: String) -> NapiResult<()> {
        self.inner.set_trailer(&name, &value).map_err(napi_error)
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
