use std::{path::PathBuf, sync::Arc};

use bon::bon;
use http::Uri;
use http::uri::Authority;

use crate::ddns::DnsScheme;
use crate::ddns::resolvers::Resolvers;
use crate::dquic::{
    Identity, Network, QuicEndpoint, binds::BindPattern, client::ClientQuicConfig,
    connection::Connection as QuicConnection, resolver::Resolve, server::ServerQuicConfig,
};
use crate::h3x::connection::ConnectionBuilder;
use crate::h3x::dquic::H3Endpoint as DquicH3Endpoint;
use crate::h3x::endpoint::H3Endpoint;

use h3x::endpoint::client::Request;
use http::Method;

pub mod client {
    //! Re-export of h3x HTTP client types.
    pub use h3x::endpoint::client::{
        AcquireError, AuthorityFrozen, Request, RequestError, Response,
    };
}

pub mod server {
    //! Re-export of h3x HTTP server types.
    pub use h3x::endpoint::server::*;
}

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

impl From<Arc<DquicH3Endpoint>> for Endpoint {
    fn from(inner: Arc<DquicH3Endpoint>) -> Self {
        Self { inner }
    }
}

/// Default STUN server for NAT traversal.
pub const STUN_SERVER: &str = "stun.genmeta.net:20004";

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
    #[snafu(display("failed to locate dhttp home"))]
    NoHome {
        source: crate::home::LocateDhttpHomeError,
    },
    #[snafu(display("failed to load identity home"))]
    LoadIdentity {
        source: crate::home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to load certificate and key"))]
    LoadSsl {
        source: crate::home::identity::ssl::LoadIdentitySslError,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(load_endpoint_from_path_error))]
pub enum LoadEndpointFromPathError {
    #[snafu(display("failed to construct identity home from path"))]
    IdentityHome {
        source: crate::home::identity::IdentityHomeFromPathError,
    },
    #[snafu(display("failed to load certificate and key"))]
    LoadSsl {
        source: crate::home::identity::ssl::LoadIdentitySslError,
    },
}

impl Endpoint {
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
    /// home directory, loads the TLS identity from
    /// `~/.dhttp/<name>/ssl/`, and constructs a QUIC endpoint with
    /// [`DnsScheme::H3`], [`DnsScheme::Mdns`], and [`DnsScheme::System`]
    /// DNS resolution schemes and a default network configuration.
    pub async fn load<N>(name: N) -> Result<Self, LoadEndpointError<N::Error>>
    where
        N: TryInto<dhttp_identity::name::DhttpName<'static>>,
        N::Error: std::error::Error + Send + Sync + 'static,
    {
        use snafu::ResultExt;

        let name = name
            .try_into()
            .context(load_endpoint_error::InvalidNameSnafu)?;
        let home = crate::home::DhttpHome::load_from_environment()
            .context(load_endpoint_error::NoHomeSnafu)?;

        let identity_home = home
            .load_identity(name)
            .await
            .context(load_endpoint_error::LoadIdentitySnafu)?;

        let identity = identity_home
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

        let identity_home = crate::home::identity::IdentityHome::try_from(path.into())
            .context(load_endpoint_from_path_error::IdentityHomeSnafu)?;
        let identity = identity_home
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
    pub fn new_request(self: &Arc<Self>) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner.new_request_owned()
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner.new_request_owned().method(Method::GET).uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner.new_request_owned().method(Method::POST).uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner.new_request_owned().method(Method::PUT).uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner
            .new_request_owned()
            .method(Method::DELETE)
            .uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner
            .new_request_owned()
            .method(Method::PATCH)
            .uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner.new_request_owned().method(Method::HEAD).uri(uri)
    }

    /// Convenience method to create an OPTIONS request for `uri`.
    pub fn options(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner
            .new_request_owned()
            .method(Method::OPTIONS)
            .uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace(&self, uri: Uri) -> Request<QuicEndpoint, Arc<DquicH3Endpoint>> {
        self.inner
            .new_request_owned()
            .method(Method::TRACE)
            .uri(uri)
    }

    pub async fn connect(
        &self,
        authority: Authority,
    ) -> Result<
        Arc<crate::h3x::connection::Connection<crate::dquic::connection::Connection>>,
        crate::h3x::pool::ConnectError<crate::dquic::ConnectError>,
    > {
        self.inner.connect(authority).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddns::DnsScheme;
    use std::fmt;

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

    #[tokio::test]
    async fn load_invalid_name() {
        // Single label without suffix/~/dot should fail at DhttpName::parse
        match Endpoint::load("invalid_single_label").await {
            Err(LoadEndpointError::InvalidName { .. }) => {}
            Err(error) => panic!("expected invalid name error, got {error:?}"),
            Ok(_) => panic!("expected invalid name error, got endpoint"),
        }
    }

    #[test]
    fn load_valid_name_parses() {
        // Valid multi-label name should parse (may fail at I/O but not at parse)
        let dname = crate::home::identity::DhttpName::parse("reimu.pilot");
        assert!(dname.is_ok());
    }

    #[tokio::test]
    async fn load_from_rejects_invalid_identity_home_path() {
        match Endpoint::load_from("/tmp/123").await {
            Err(LoadEndpointFromPathError::IdentityHome { .. }) => {}
            Err(error) => panic!("expected identity home error, got {error:?}"),
            Ok(_) => panic!("expected identity home error, got endpoint"),
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
            "publisher.example.com".parse().unwrap(),
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

    #[test]
    fn endpoint_implements_quic_listen() {
        fn assert_listen<T: crate::h3x::quic::Listen>() {}

        assert_listen::<Endpoint>();
    }
}
