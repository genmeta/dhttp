use std::{path::PathBuf, sync::Arc};

use bon::bon;
use http::uri::Authority;
use snafu::ResultExt;

use crate::ddns::DnsScheme;
use crate::ddns::resolvers::Resolvers;
use crate::dquic::{
    Identity, Network, QuicEndpoint, binds::BindPattern, client::ClientQuicConfig,
    connection::Connection as QuicConnection, resolver::Resolve, server::ServerQuicConfig,
};
use crate::h3x::connection::ConnectionBuilder;
use crate::h3x::dquic::H3Endpoint as DquicH3Endpoint;
use crate::h3x::endpoint::H3Endpoint;
use crate::message::{IntoAuthority, IntoAuthorityError, IntoUri, Message};

use http::Method;

pub mod client;
pub mod server;

use self::client::Request;

/// A DHttp endpoint bound to a QUIC connection.
///
/// Provides both HTTP client and server capabilities over a single
/// QUIC transport. Use [`Endpoint::load`] for the simplest setup from
/// a domain identity, or [`Endpoint::builder`] for full control over
/// DNS schemes, network configuration, and TLS identity.
///
/// The endpoint is cheaply cloneable (wraps an `Arc`).
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<DquicH3Endpoint>,
}

impl TryFrom<Arc<DquicH3Endpoint>> for Endpoint {
    type Error = InvalidEndpointIdentityError;

    fn try_from(inner: Arc<DquicH3Endpoint>) -> Result<Self, Self::Error> {
        Self::validate_identity(inner.quic().identity().as_deref())?;
        Ok(Self { inner })
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(invalid_endpoint_identity_error))]
pub enum InvalidEndpointIdentityError {
    #[snafu(display("endpoint identity is not a dhttp name"))]
    InvalidName {
        source: dhttp_identity::name::InvalidDhttpName,
    },
}

/// Default STUN server for NAT traversal.
///
/// STUN server resolution uses this authority so the well-known port remains
/// part of the query. TODO: separate the network STUN resolver from the
/// endpoint H3 resolver so the Network default can resolve this through DHTTP
/// DNS without a construction cycle.
pub const STUN_SERVER: &str = crate::bootstrap::DHTTP_STUN_SERVER;

/// Build an [`H3Resolver`] backed by a dedicated DNS-only [`QuicEndpoint`].
///
/// The internal endpoint shares the caller's [`Network`] and bind patterns
/// so DNS queries reuse the same UDP sockets and [`QuicRouter`]. It does not
/// accept incoming connections — the identity, if any, is passed for client
/// authentication only.
async fn create_h3_dns_endpoint(
    identity: Option<Arc<Identity>>,
    network: Arc<Network>,
    client_config: &ClientQuicConfig,
    bind: Arc<Vec<BindPattern>>,
) -> Arc<H3Endpoint<QuicEndpoint, QuicConnection>> {
    let quic = QuicEndpoint::builder()
        .network(network)
        .maybe_identity(identity)
        .client(client_config.clone())
        .bind(bind)
        .build()
        .await;
    Arc::new(H3Endpoint::new(quic))
}

#[bon]
impl Endpoint {
    /// Construct a new endpoint with full configuration control.
    ///
    /// Use the builder pattern (via [`Endpoint::builder`]) to configure
    /// DNS schemes, network, identity, client/server config, and bind
    /// patterns. For a simpler setup from a domain name, see
    /// [`Endpoint::load`].
    #[builder]
    pub async fn new(
        #[builder(field)] dns_schemes: Vec<DnsScheme>,

        identity: Option<Arc<Identity>>,
        network: Option<Arc<Network>>,

        #[builder(default = crate::trust::default_client_quic_config())] client: ClientQuicConfig,
        #[builder(default = crate::trust::default_server_quic_config())] server: ServerQuicConfig,
        #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
        resolver: Option<Arc<dyn Resolve + Send + Sync>>,
        #[builder(default)] connection_builder: Arc<ConnectionBuilder<QuicConnection>>,
    ) -> Self {
        Self::validate_identity(identity.as_deref())
            .expect("BUG: dhttp endpoint identity must be a valid dhttp name");

        let network = network.unwrap_or_else(|| {
            Network::builder()
                .stun_server(Arc::<str>::from(STUN_SERVER))
                .build()
        });

        let quic_resolver: Arc<dyn Resolve + Send + Sync> = match resolver {
            Some(resolver) => resolver,
            None => {
                let mut resolvers = Resolvers::builder();

                if dns_schemes.contains(&DnsScheme::Mdns) {
                    resolvers = resolvers.mdns(network.clone(), bind.clone()).await;
                }

                if dns_schemes.contains(&DnsScheme::System) {
                    resolvers = resolvers.system();
                }

                if dns_schemes.contains(&DnsScheme::Http) {
                    resolvers = resolvers
                        .http()
                        .expect("BUG: DHTTP HTTP DNS server is a valid URL");
                }

                if dns_schemes.contains(&DnsScheme::H3) {
                    let h3 = create_h3_dns_endpoint(
                        identity.clone(),
                        network.clone(),
                        &client,
                        bind.clone(),
                    )
                    .await;
                    resolvers = resolvers
                        .h3(h3)
                        .expect("BUG: DHTTP H3 DNS server is a valid URL");
                }

                Arc::new(resolvers.build())
            }
        };
        let quic = QuicEndpoint::builder()
            .network(network)
            .maybe_identity(identity)
            .resolver(quic_resolver)
            .client(client)
            .server(server)
            .bind(bind)
            .build()
            .await;

        let h3 = H3Endpoint::builder()
            .quic(quic)
            .builder(connection_builder)
            .build();
        Self {
            inner: Arc::new(h3),
        }
    }
}

impl<S: endpoint_builder::State> EndpointBuilder<S> {
    pub fn dns(mut self, scheme: DnsScheme) -> Self {
        self.dns_schemes.push(scheme);
        self
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(load_endpoint_error))]
pub enum LoadEndpointError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    #[snafu(display("failed to parse dhttp name"))]
    InvalidName { source: E },
    #[snafu(display("failed to locate dhttp config"))]
    NoConfig {
        source: crate::config::LocateDhttpConfigError,
    },
    #[snafu(display("failed to load identity config"))]
    LoadIdentity {
        source: crate::config::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to load certificate and key"))]
    LoadSsl {
        source: crate::config::identity::ssl::LoadIdentitySslError,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(load_endpoint_from_path_error))]
pub enum LoadEndpointFromPathError {
    #[snafu(display("failed to construct identity config from path"))]
    IdentityConfig {
        source: crate::config::identity::IdentityConfigFromPathError,
    },
    #[snafu(display("failed to load certificate and key"))]
    LoadSsl {
        source: crate::config::identity::ssl::LoadIdentitySslError,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(connect_error))]
pub enum ConnectError {
    #[snafu(display("failed to convert connection authority"))]
    Authority { source: IntoAuthorityError },
    #[snafu(display("failed to connect endpoint"))]
    Connect {
        source: crate::h3x::pool::ConnectError<crate::dquic::ConnectError>,
    },
}

impl Endpoint {
    fn validate_identity(identity: Option<&Identity>) -> Result<(), InvalidEndpointIdentityError> {
        if let Some(identity) = identity {
            Self::name_from_identity(identity)?;
        }
        Ok(())
    }

    pub(crate) fn name_from_identity(
        identity: &Identity,
    ) -> Result<dhttp_identity::name::DhttpName<'static>, InvalidEndpointIdentityError> {
        dhttp_identity::name::DhttpName::try_from(identity.name().clone())
            .context(invalid_endpoint_identity_error::InvalidNameSnafu)
    }

    fn request(&self) -> Request {
        let msg = Message::unresolved_request();
        let state = Arc::new(client::RequestState::new(self.inner.clone(), msg));
        Request::new(state)
    }

    /// Return a shared reference to the inner [`DquicH3Endpoint`].
    pub fn as_h3(&self) -> Arc<DquicH3Endpoint> {
        self.inner.clone()
    }

    /// Return the shared QUIC network used by this endpoint.
    pub fn network(&self) -> Arc<Network> {
        self.inner.quic().network().clone()
    }

    /// Return the TLS identity used by this endpoint, if any.
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.inner.quic().identity()
    }

    /// Return the DHttp name used by this endpoint, if any.
    pub fn name(&self) -> Option<dhttp_identity::name::DhttpName<'static>> {
        self.identity().map(|identity| {
            Self::name_from_identity(&identity)
                .expect("BUG: dhttp endpoint identity must be a valid dhttp name")
        })
    }

    /// Return the DNS resolver set used by this endpoint.
    pub fn resolver(&self) -> Arc<dyn Resolve + Send + Sync> {
        self.inner.quic().resolver().clone()
    }

    /// Return the bind patterns owned by this endpoint.
    pub fn bind_patterns(&self) -> Arc<Vec<BindPattern>> {
        self.inner.quic().bind_patterns().clone()
    }

    pub fn publisher(&self) -> Result<crate::ddns::Publisher, crate::ddns::CreatePublisherError> {
        self.publisher_with_options(crate::ddns::PublishOptions::default())
    }

    pub fn publisher_with_options(
        &self,
        options: crate::ddns::PublishOptions,
    ) -> Result<crate::ddns::Publisher, crate::ddns::CreatePublisherError> {
        let identity = self
            .identity()
            .ok_or(crate::ddns::CreatePublisherError::AnonymousEndpoint)?;
        let identity: Arc<dyn dhttp_identity::identity::LocalAgent> = identity;
        Ok(crate::ddns::Publisher::new(
            identity,
            self.network(),
            self.resolver(),
            self.bind_patterns(),
        )
        .with_options(options))
    }

    /// Load an endpoint from a domain name.
    ///
    /// Accepts a [`dhttp_identity::name::DhttpName`], locates the `.dhttp`
    /// config directory, loads the TLS identity from
    /// `~/.dhttp/<name>/ssl/`, and constructs a QUIC endpoint with
    /// [`DnsScheme::H3`], [`DnsScheme::Mdns`], and [`DnsScheme::System`]
    /// DNS resolution schemes and a default network configuration.
    pub async fn load<'a, N>(name: N) -> Result<Self, LoadEndpointError<N::Error>>
    where
        N: TryInto<dhttp_identity::name::DhttpName<'a>>,
        N::Error: std::error::Error + Send + Sync + 'static,
    {
        use snafu::ResultExt;

        let name = name
            .try_into()
            .context(load_endpoint_error::InvalidNameSnafu)?;
        let config = crate::config::DhttpConfig::load_from_environment()
            .context(load_endpoint_error::NoConfigSnafu)?;

        let identity_config = config
            .load_identity(name)
            .await
            .context(load_endpoint_error::LoadIdentitySnafu)?;

        let identity = identity_config
            .identity()
            .await
            .context(load_endpoint_error::LoadSslSnafu)?;

        let endpoint = Self::builder()
            .identity(Arc::new(identity))
            .dns(DnsScheme::H3)
            .dns(DnsScheme::Mdns)
            .dns(DnsScheme::System)
            .build()
            .await;

        Ok(endpoint)
    }

    pub async fn load_from(path: impl Into<PathBuf>) -> Result<Self, LoadEndpointFromPathError> {
        use snafu::ResultExt;

        let identity_config = crate::config::identity::IdentityConfig::try_from(path.into())
            .context(load_endpoint_from_path_error::IdentityConfigSnafu)?;
        let identity = identity_config
            .identity()
            .await
            .context(load_endpoint_from_path_error::LoadSslSnafu)?;

        let endpoint = Self::builder()
            .identity(Arc::new(identity))
            .dns(DnsScheme::H3)
            .dns(DnsScheme::Mdns)
            .dns(DnsScheme::System)
            .build()
            .await;

        Ok(endpoint)
    }

    /// Create a new HTTP request owned by this endpoint.
    ///
    /// Authority is NOT set at construction time — use [`.uri()`] on
    /// the returned [`Request`] to set both the request URI and the
    /// authority.
    ///
    /// [`Request`]: Request
    /// [`.uri()`]: Request::uri
    pub fn new_request(self: &Arc<Self>) -> Request {
        let msg = Message::unresolved_request();
        let state = Arc::new(client::RequestState::new(self.inner.clone(), msg));
        Request::new(state)
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::GET).uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::POST).uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::PUT).uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::DELETE).uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::PATCH).uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::HEAD).uri(uri)
    }

    /// Convenience method to create an OPTIONS request for `uri`.
    pub fn options(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::OPTIONS).uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace(&self, uri: impl IntoUri) -> Request {
        self.request().method(Method::TRACE).uri(uri)
    }

    pub async fn connect(
        &self,
        authority: impl IntoAuthority,
    ) -> Result<
        Arc<crate::h3x::connection::Connection<crate::dquic::connection::Connection>>,
        ConnectError,
    > {
        let name = self.name();
        let authority = authority
            .into_authority(name.as_ref())
            .context(connect_error::AuthoritySnafu)?;
        self.inner
            .connect(authority)
            .await
            .context(connect_error::ConnectSnafu)
    }

    /// Serve HTTP/3 requests on this endpoint.
    ///
    /// The returned future does not capture `&self`, so it can be
    /// spawned:
    ///
    /// ```ignore
    /// let ep: Arc<Endpoint> = ...;
    /// tokio::spawn(ep.serve(router));
    /// ```
    pub fn serve<S>(
        &self,
        service: S,
    ) -> impl Future<Output = Result<(), h3x::dquic::AcceptError>> + use<S>
    where
        S: tower_service::Service<server::UnresolvedRequest, Response = ()>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.inner.serve_owned(service)
    }
}

impl crate::h3x::quic::Listen for Endpoint {
    type Connection = QuicConnection;
    type Error = crate::h3x::dquic::AcceptError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        self.inner.quic().accept().await
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        crate::h3x::quic::Listen::shutdown(&self.inner.quic()).await
    }
}

impl crate::h3x::quic::Connect for Endpoint {
    type Connection = QuicConnection;
    type Error = crate::dquic::ConnectError;

    async fn connect(&self, server: &Authority) -> Result<Arc<Self::Connection>, Self::Error> {
        crate::h3x::quic::Connect::connect(self.inner.quic(), server).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddns::DnsScheme;
    use std::fmt;

    #[test]
    fn stun_server_comes_from_compile_time_environment() {
        if let Some(expected) = option_env!("DHTTP_STUN_SERVER") {
            assert_eq!(STUN_SERVER, expected);
        }
    }

    #[tokio::test]
    async fn check_builder_api() {
        let endpoint = Arc::new(
            Endpoint::builder()
                .dns(DnsScheme::Mdns)
                .dns(DnsScheme::H3)
                .build()
                .await,
        );
        let _ = endpoint.new_request();
    }

    #[test]
    fn endpoint_implements_quic_connect() {
        fn assert_connect<C: crate::h3x::quic::Connect>() {}

        assert_connect::<Endpoint>();
        assert_connect::<Arc<Endpoint>>();
    }

    #[tokio::test]
    async fn load_invalid_name() {
        match Endpoint::load("!!!").await {
            Err(LoadEndpointError::InvalidName { .. }) => {}
            Err(error) => panic!("expected invalid name error, got {error:?}"),
            Ok(_) => panic!("expected invalid name error, got endpoint"),
        }
    }

    #[test]
    fn load_valid_name_parses() {
        // Valid multi-label name should parse (may fail at I/O but not at parse)
        let dname = "reimu.pilot".parse::<crate::name::DhttpName>();
        assert!(dname.is_ok());
    }

    #[tokio::test]
    async fn load_from_rejects_invalid_identity_config_path() {
        match Endpoint::load_from("/tmp/123").await {
            Err(LoadEndpointFromPathError::IdentityConfig { .. }) => {}
            Err(error) => panic!("expected identity config error, got {error:?}"),
            Ok(_) => panic!("expected identity config error, got endpoint"),
        }
    }

    #[tokio::test]
    async fn publisher_rejects_anonymous_endpoint() {
        let endpoint = Endpoint::builder().build().await;
        let error = endpoint.publisher().unwrap_err();
        assert!(matches!(
            error,
            crate::ddns::CreatePublisherError::AnonymousEndpoint
        ));
    }

    #[derive(Debug)]
    struct MarkerResolver;

    impl fmt::Display for MarkerResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("marker resolver")
        }
    }

    impl crate::dquic::qresolve::Resolve for MarkerResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> crate::dquic::qresolve::ResolveFuture<'l> {
            use futures::{FutureExt, StreamExt, stream};
            async { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    #[tokio::test]
    async fn builder_accepts_explicit_resolver() {
        let resolver: Arc<dyn crate::dquic::qresolve::Resolve + Send + Sync> =
            Arc::new(MarkerResolver);

        let endpoint = Endpoint::builder().resolver(resolver).build().await;
        let resolver = endpoint.resolver();
        let any: &dyn std::any::Any = resolver.as_ref();

        assert!(any.downcast_ref::<MarkerResolver>().is_some());
    }

    #[tokio::test]
    async fn publisher_can_apply_publish_options() {
        use rustls::pki_types::PrivateKeyDer;

        let identity = Identity::new(
            "publisher.example.com.genmeta.net".parse().unwrap(),
            Vec::new(),
            PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
        );
        let endpoint = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await;

        let publisher = endpoint
            .publisher_with_options(crate::ddns::PublishOptions { server_id: Some(7) })
            .expect("named endpoint can publish");

        assert_eq!(publisher.options().server_id, Some(7));
    }

    #[tokio::test]
    async fn endpoint_name_returns_dhttp_identity_name() {
        use rustls::pki_types::PrivateKeyDer;

        let identity = Identity::new(
            "client.example.com.genmeta.net".parse().unwrap(),
            Vec::new(),
            PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
        );
        let endpoint = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await;

        let name = endpoint.name().expect("named endpoint has a dhttp name");

        assert_eq!(name.as_full(), "client.example.com.genmeta.net");
    }

    #[tokio::test]
    async fn request_uri_accepts_str_and_returns_bare_tilde_error_on_first_io() {
        let endpoint = Endpoint::builder().build().await;

        let error = match endpoint.get("https://~/api").into_response().await {
            Ok(_) => panic!("bare tilde request should fail before opening a stream"),
            Err(error) => error,
        };

        match error {
            client::RequestError::MalformedRequest { source } => match source.as_ref() {
                client::MalformedRequestError::Uri {
                    source:
                        crate::message::IntoUriError::Authority {
                            source:
                                crate::message::IntoAuthorityError::Expand {
                                    source: crate::name::ExpandAuthorityError::MissingBaseName,
                                },
                        },
                } => {}
                other => panic!("expected dhttp uri expansion error, got {other:?}"),
            },
            other => panic!("expected malformed request error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_uri_parse_error_is_returned_on_first_io() {
        let endpoint = Endpoint::builder().build().await;

        let error = match endpoint.get("://not a uri").into_response().await {
            Ok(_) => panic!("invalid uri request should fail before opening a stream"),
            Err(error) => error,
        };

        match error {
            client::RequestError::MalformedRequest { source } => match source.as_ref() {
                client::MalformedRequestError::Uri { .. } => {}
                other => panic!("expected request uri conversion error, got {other:?}"),
            },
            other => panic!("expected malformed request error, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_implements_quic_listen() {
        fn assert_listen<T: crate::h3x::quic::Listen>() {}

        assert_listen::<Endpoint>();
    }
}
