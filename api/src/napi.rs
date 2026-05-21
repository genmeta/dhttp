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
}
