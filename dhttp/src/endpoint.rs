use std::{path::PathBuf, str::FromStr, sync::Arc};

use bon::bon;
use http::uri::Authority;
use snafu::{OptionExt, ResultExt};

use crate::ddns::resolvers::{DHTTP_H3_DNS_SERVER, DnsScheme, H3Resolver};
use crate::dquic::{
    Identity, QuicEndpoint, binds::BindPattern, client::ClientQuicConfig,
    connection::Connection as QuicConnection, resolver::Resolve, server::ServerQuicConfig,
};
use crate::h3x::connection::ConnectionBuilder;
use crate::h3x::dquic::H3Endpoint as DquicH3Endpoint;
use crate::h3x::endpoint::H3Endpoint;
use crate::message::{IntoAuthority, IntoAuthorityError, IntoUri};

use http::Method;

pub mod client;
pub mod server;

use self::client::Request;
use crate::network::{
    ArcResolver, BuildEndpointDnsError, BuildStunDnsError, DhttpNetwork, EndpointDnsPlan,
};

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
    network: DhttpNetwork,
    publishers: crate::ddns::publishers::Publishers,
}

impl TryFrom<Arc<DquicH3Endpoint>> for Endpoint {
    type Error = InvalidEndpointIdentityError;

    fn try_from(inner: Arc<DquicH3Endpoint>) -> Result<Self, Self::Error> {
        Self::validate_identity(inner.quic().identity().as_deref())?;
        let network = DhttpNetwork::from(inner.quic().network().clone());
        Ok(Self {
            inner,
            network,
            publishers: crate::ddns::publishers::Publishers::new(),
        })
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(invalid_endpoint_identity_error))]
pub enum InvalidEndpointIdentityError {
    #[snafu(display("endpoint identity is not a dhttp name"))]
    InvalidName {
        source: dhttp_identity::name::InvalidDhttpName,
    },
    #[snafu(display("endpoint identity certificate metadata is invalid"))]
    InvalidCertificateMetadata {
        source: dhttp_identity::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(build_endpoint_error))]
pub enum BuildEndpointError {
    #[snafu(display("invalid endpoint identity"))]
    InvalidIdentity {
        source: InvalidEndpointIdentityError,
    },
    #[snafu(display("failed to build endpoint dns"))]
    EndpointDns { source: BuildEndpointDnsError },
    #[snafu(display("failed to build stun dns"))]
    StunDns { source: BuildStunDnsError },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(create_endpoint_publication_loop_error))]
pub enum CreateEndpointPublicationLoopError {
    #[snafu(display("anonymous endpoint cannot publish dns records"))]
    AnonymousEndpoint,
}

/// Default STUN server for NAT traversal.
///
/// STUN server resolution uses this authority so the well-known port remains
/// part of the query.
pub const STUN_SERVER: &str = crate::bootstrap::DHTTP_STUN_SERVER;

fn normalize_bind(bind: Arc<Vec<BindPattern>>) -> Arc<Vec<BindPattern>> {
    if bind.is_empty() {
        Arc::new(vec![
            BindPattern::from_str("*").expect("BUG: wildcard bind pattern is valid"),
        ])
    } else {
        bind
    }
}

fn h3_resolver_from_quic(quic: QuicEndpoint) -> H3Resolver<QuicEndpoint> {
    let h3 = Arc::new(H3Endpoint::new(quic));
    H3Resolver::from_endpoint(DHTTP_H3_DNS_SERVER, h3)
        .expect("BUG: DHTTP H3 DNS server is a valid URL")
}

fn h3_resolver_arc_from_quic(quic: QuicEndpoint) -> ArcResolver {
    Arc::new(h3_resolver_from_quic(quic))
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
        #[builder(field)] dns_plan: EndpointDnsPlan,

        identity: Option<Arc<Identity>>,
        network: Option<DhttpNetwork>,

        #[builder(default = crate::trust::default_client_quic_config())] client: ClientQuicConfig,
        #[builder(default = crate::trust::default_server_quic_config())] server: ServerQuicConfig,
        #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
        #[builder(default)] connection_builder: Arc<ConnectionBuilder<QuicConnection>>,
    ) -> Result<Self, BuildEndpointError> {
        Self::validate_identity(identity.as_deref())
            .context(build_endpoint_error::InvalidIdentitySnafu)?;

        let bind = normalize_bind(bind);
        let (mut network, owns_network) = match network {
            Some(network) => (network, false),
            None => (DhttpNetwork::endpoint_owned(), true),
        };
        let raw_network = network.network().clone();

        let built_dns = dns_plan
            .build_endpoint_dns(raw_network.clone(), bind.clone())
            .await
            .context(build_endpoint_error::EndpointDnsSnafu)?;

        let quic = QuicEndpoint::builder()
            .network(raw_network.clone())
            .maybe_identity(identity)
            .resolver(built_dns.endpoint_resolver.clone())
            .client(client.clone())
            .server(server)
            .bind(bind.clone())
            .build()
            .await;

        if let Some(endpoint_h3_deferred) = built_dns.endpoint_h3_deferred {
            let mut dns_quic = quic.clone();
            dns_quic.set_resolver(built_dns.endpoint_h3_underlay.clone());
            endpoint_h3_deferred
                .set(h3_resolver_from_quic(dns_quic))
                .expect("BUG: endpoint H3 resolver is set exactly once");
        }

        if owns_network {
            let stun_h3_resolver = if dns_plan.uses_h3() {
                let stun_quic = QuicEndpoint::builder()
                    .network(raw_network.clone())
                    .resolver(built_dns.endpoint_h3_underlay)
                    .client(client)
                    .bind(bind.clone())
                    .build()
                    .await;
                Some(h3_resolver_arc_from_quic(stun_quic))
            } else {
                None
            };
            let stun_dns = dns_plan
                .build_stun_dns(stun_h3_resolver, raw_network, bind.clone())
                .await
                .context(build_endpoint_error::StunDnsSnafu)?;
            network.finish_stun_resolver(stun_dns);
        }

        let h3 = H3Endpoint::builder()
            .quic(quic)
            .builder(connection_builder)
            .build();
        Ok(Self {
            inner: Arc::new(h3),
            network,
            publishers: built_dns.endpoint_publishers,
        })
    }
}

impl<S: endpoint_builder::State> EndpointBuilder<S> {
    pub fn dns(mut self, scheme: DnsScheme) -> Self {
        self.dns_plan.push_dns(scheme);
        self
    }

    pub fn resolver(mut self, resolver: Arc<dyn Resolve + Send + Sync>) -> Self {
        self.dns_plan.push_resolver(resolver);
        self
    }

    pub fn publisher(
        mut self,
        scope: crate::ddns::publishers::PublishScope,
        publisher: Arc<dyn crate::dquic::resolver::Publish + Send + Sync>,
    ) -> Self {
        self.dns_plan.push_publisher(scope, publisher);
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
    #[snafu(display("failed to resolve identity profile"))]
    ResolveIdentityProfile {
        source: crate::home::identity::ssl::ResolveIdentityProfileError,
    },
    #[snafu(display("failed to load identity"))]
    LoadIdentity {
        source: crate::home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to build endpoint"))]
    BuildEndpoint { source: BuildEndpointError },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(load_endpoint_from_path_error))]
pub enum LoadEndpointFromPathError {
    #[snafu(display("failed to construct identity profile from path"))]
    IdentityProfile {
        source: crate::home::identity::IdentityProfileFromPathError,
    },
    #[snafu(display("failed to load identity"))]
    LoadIdentity {
        source: crate::home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to build endpoint"))]
    BuildEndpoint { source: BuildEndpointError },
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
            identity
                .dhttp_subject_key_identifier()
                .context(invalid_endpoint_identity_error::InvalidCertificateMetadataSnafu)?;
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
        let state = Arc::new(client::RequestState::new(self.inner.clone()));
        Request::new(state)
    }

    /// Return a shared reference to the inner [`DquicH3Endpoint`].
    pub fn as_h3(&self) -> Arc<DquicH3Endpoint> {
        self.inner.clone()
    }

    /// Return the shared QUIC network used by this endpoint.
    pub fn network(&self) -> &DhttpNetwork {
        &self.network
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

    pub fn dns_publishers(&self) -> &crate::ddns::publishers::Publishers {
        &self.publishers
    }

    /// Return the bind patterns owned by this endpoint.
    pub fn bind_patterns(&self) -> Arc<Vec<BindPattern>> {
        self.inner.quic().bind_patterns().clone()
    }

    pub fn dns_publication_loop(
        &self,
    ) -> Result<
        crate::ddns::publishers::EndpointPublicationLoop<
            crate::ddns::publishers::EndpointBindingAddresses,
        >,
        CreateEndpointPublicationLoopError,
    > {
        let identity = self
            .identity()
            .context(create_endpoint_publication_loop_error::AnonymousEndpointSnafu)?;
        let name = identity.name().to_owned();
        let source = crate::ddns::publishers::EndpointBindingAddresses::new(
            self.network().network().clone(),
            self.bind_patterns(),
        );
        Ok(crate::ddns::publishers::EndpointPublicationLoop::new(
            name,
            self.publishers.clone(),
            source,
        ))
    }

    /// Load an endpoint from a domain name.
    ///
    /// Accepts a [`dhttp_identity::name::DhttpName`], locates the `.dhttp`
    /// home directory, loads the TLS identity from
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
        let home = crate::home::DhttpHome::load_from_environment()
            .context(load_endpoint_error::NoHomeSnafu)?;

        let profile = home
            .resolve_identity_profile(name)
            .await
            .context(load_endpoint_error::ResolveIdentityProfileSnafu)?;

        let identity = profile
            .load_identity()
            .await
            .context(load_endpoint_error::LoadIdentitySnafu)?;

        let endpoint = Self::builder()
            .identity(Arc::new(identity))
            .dns(DnsScheme::H3)
            .dns(DnsScheme::Mdns)
            .dns(DnsScheme::System)
            .build()
            .await
            .context(load_endpoint_error::BuildEndpointSnafu)?;

        Ok(endpoint)
    }

    pub async fn load_from(path: impl Into<PathBuf>) -> Result<Self, LoadEndpointFromPathError> {
        use snafu::ResultExt;

        let profile = crate::home::identity::IdentityProfile::try_from(path.into())
            .context(load_endpoint_from_path_error::IdentityProfileSnafu)?;
        let identity = profile
            .load_identity()
            .await
            .context(load_endpoint_from_path_error::LoadIdentitySnafu)?;

        let endpoint = Self::builder()
            .identity(Arc::new(identity))
            .dns(DnsScheme::H3)
            .dns(DnsScheme::Mdns)
            .dns(DnsScheme::System)
            .build()
            .await
            .context(load_endpoint_from_path_error::BuildEndpointSnafu)?;

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
        let state = Arc::new(client::RequestState::new(self.inner.clone()));
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

    /// Listen for HTTP/3 requests on this endpoint.
    ///
    /// The returned future does not capture `&self`, so it can be
    /// spawned:
    ///
    /// ```ignore
    /// let ep: Arc<Endpoint> = ...;
    /// tokio::spawn(ep.listen(router));
    /// ```
    #[doc(alias = "serve")]
    pub fn listen<S>(
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
        let publisher_loop = self.dns_publication_loop();
        let h3 = self.inner.clone();
        async move {
            let publisher_loop = match publisher_loop {
                Ok(publisher_loop) => publisher_loop,
                Err(CreateEndpointPublicationLoopError::AnonymousEndpoint) => {
                    return Err(crate::h3x::dquic::AcceptError::ServerUnavailable);
                }
            };

            let listen = h3.listen_owned(service);
            let publish = publisher_loop.run();
            futures::pin_mut!(listen);
            futures::pin_mut!(publish);

            match futures::future::select(listen, publish).await {
                futures::future::Either::Left((result, _publish)) => result,
                futures::future::Either::Right((never, _listen)) => match never {},
            }
        }
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
    use crate::{
        ddns::resolvers::{DnsScheme, Resolvers},
        dquic::Network,
        network::DeferredStunResolver,
    };
    use std::{
        any::Any,
        fmt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    fn test_identity(name: &str, der: &'static [u8]) -> Identity {
        Identity::new(
            name.parse().unwrap(),
            vec![CertificateDer::from(der.to_vec())],
            PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
        )
    }

    fn valid_dhttp_identity(name: &str) -> Identity {
        test_identity(
            name,
            include_bytes!("../../identity/tests/fixtures/valid.der"),
        )
    }

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
                .await
                .expect("anonymous endpoint is valid"),
        );
        let _ = endpoint.new_request();
    }

    #[tokio::test]
    async fn builder_rejects_non_dhttp_identity() {
        let identity = valid_dhttp_identity("example.com");

        let Err(error) = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await
        else {
            panic!("non-dhttp endpoint identity must be rejected by build");
        };

        assert!(matches!(
            error,
            BuildEndpointError::InvalidIdentity {
                source: InvalidEndpointIdentityError::InvalidName { .. }
            }
        ));
    }

    #[tokio::test]
    async fn builder_rejects_dhttp_identity_without_subject_key_identifier() {
        let identity = test_identity(
            "missing.example.com.dhttp.net",
            include_bytes!("../../identity/tests/fixtures/missing.der"),
        );

        let Err(error) = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await
        else {
            panic!("dhttp endpoint identity without ski must be rejected by build");
        };

        assert!(matches!(
            error,
            BuildEndpointError::InvalidIdentity {
                source: InvalidEndpointIdentityError::InvalidCertificateMetadata { .. }
            }
        ));
    }

    #[tokio::test]
    async fn builder_rejects_dhttp_identity_with_malformed_subject_key_identifier() {
        let identity = test_identity(
            "malformed.example.com.dhttp.net",
            include_bytes!("../../identity/tests/fixtures/malformed.der"),
        );

        let Err(error) = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await
        else {
            panic!("dhttp endpoint identity with malformed ski must be rejected by build");
        };

        assert!(matches!(
            error,
            BuildEndpointError::InvalidIdentity {
                source: InvalidEndpointIdentityError::InvalidCertificateMetadata { .. }
            }
        ));
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
            Err(LoadEndpointFromPathError::IdentityProfile { .. }) => {}
            Err(error) => panic!("expected identity profile error, got {error:?}"),
            Ok(_) => panic!("expected identity profile error, got endpoint"),
        }
    }

    #[derive(Clone)]
    struct NoopService;

    impl tower_service::Service<server::UnresolvedRequest> for NoopService {
        type Response = ();
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: server::UnresolvedRequest) -> Self::Future {
            std::future::ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn listen_maps_anonymous_publisher_to_server_unavailable() {
        let endpoint = Endpoint::builder().build().await.unwrap();

        let error = endpoint
            .listen(NoopService)
            .await
            .expect_err("anonymous publishing endpoint cannot listen");

        assert!(matches!(
            error,
            crate::h3x::dquic::AcceptError::ServerUnavailable
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
    async fn endpoint_default_builds_dns_publishers() {
        let endpoint = Endpoint::builder()
            .build()
            .await
            .expect("anonymous endpoint is valid");

        assert!(endpoint.dns_publishers().iter().next().is_some());
    }

    #[tokio::test]
    async fn endpoint_with_custom_resolver_only_has_no_dns_publishers() {
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(MarkerResolver);
        let endpoint = Endpoint::builder()
            .resolver(resolver)
            .build()
            .await
            .expect("anonymous endpoint is valid");

        assert!(endpoint.dns_publishers().iter().next().is_none());
    }

    #[derive(Debug)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }

    impl fmt::Display for CountingResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("counting resolver")
        }
    }

    impl crate::dquic::qresolve::Resolve for CountingResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> crate::dquic::qresolve::ResolveFuture<'l> {
            use futures::{FutureExt, StreamExt, stream};

            self.calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    #[derive(Debug)]
    struct CountingPublisher {
        calls: Arc<AtomicUsize>,
    }

    impl fmt::Display for CountingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("counting publisher")
        }
    }

    impl crate::dquic::resolver::Publish for CountingPublisher {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            _packet: &'a [u8],
        ) -> crate::dquic::resolver::PublishFuture<'a> {
            use futures::FutureExt;

            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(()) }.boxed()
        }
    }

    fn endpoint_resolver_names(endpoint: &Endpoint) -> Vec<String> {
        let resolver = endpoint.resolver();
        let any: &dyn Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("endpoint resolver should be an aggregate");
        resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect()
    }

    #[tokio::test]
    async fn endpoint_with_custom_resolver_only_uses_custom_resolver_chain() {
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(MarkerResolver);
        let endpoint = Endpoint::builder()
            .resolver(resolver)
            .build()
            .await
            .expect("custom resolver endpoint is valid");

        assert!(endpoint.dns_publishers().iter().next().is_none());
        assert_eq!(endpoint_resolver_names(&endpoint), vec!["marker resolver"]);
    }

    #[tokio::test]
    async fn endpoint_with_publisher_only_fails_empty_resolver() {
        let publisher: Arc<dyn crate::dquic::resolver::Publish + Send + Sync> =
            Arc::new(CountingPublisher {
                calls: Arc::new(AtomicUsize::new(0)),
            });
        let Err(error) = Endpoint::builder()
            .publisher(crate::ddns::publishers::PublishScope::WideArea, publisher)
            .build()
            .await
        else {
            panic!("publisher-only endpoint should fail without resolver");
        };

        assert!(matches!(error, BuildEndpointError::EndpointDns { .. }));
    }

    #[tokio::test]
    async fn endpoint_with_system_dns_and_custom_publisher_builds_both_sides() {
        let publisher: Arc<dyn crate::dquic::resolver::Publish + Send + Sync> =
            Arc::new(CountingPublisher {
                calls: Arc::new(AtomicUsize::new(0)),
            });
        let endpoint = Endpoint::builder()
            .dns(DnsScheme::System)
            .publisher(crate::ddns::publishers::PublishScope::WideArea, publisher)
            .build()
            .await
            .expect("system plus custom publisher endpoint should build");

        assert_eq!(endpoint_resolver_names(&endpoint), vec!["System DNS Resolver"]);
        assert_eq!(endpoint.dns_publishers().iter().count(), 1);
    }

    #[tokio::test]
    async fn builder_accepts_explicit_resolver() {
        let resolver: Arc<dyn crate::dquic::qresolve::Resolve + Send + Sync> =
            Arc::new(MarkerResolver);

        let endpoint = Endpoint::builder()
            .resolver(resolver)
            .build()
            .await
            .unwrap();
        let resolver = endpoint.resolver();
        let any: &dyn std::any::Any = resolver.as_ref();

        assert!(any.downcast_ref::<MarkerResolver>().is_some());
    }

    #[tokio::test]
    async fn owned_network_with_custom_resolver_uses_custom_for_stun_resolution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver {
            calls: calls.clone(),
        });

        let endpoint = Endpoint::builder()
            .resolver(resolver)
            .build()
            .await
            .unwrap();
        let _records = endpoint
            .network()
            .network()
            .quic()
            .stun_resolver()
            .lookup("stun.example.test:3478")
            .await
            .expect("custom STUN resolver should be called");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn external_network_is_not_mutated_by_endpoint_builder() {
        let external_calls = Arc::new(AtomicUsize::new(0));
        let endpoint_calls = Arc::new(AtomicUsize::new(0));
        let external_resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver {
            calls: external_calls,
        });
        let endpoint_resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver {
            calls: endpoint_calls,
        });
        let raw_network = Network::builder()
            .stun_resolver(external_resolver.clone())
            .build();

        let endpoint = Endpoint::builder()
            .network(DhttpNetwork::from(raw_network.clone()))
            .resolver(endpoint_resolver.clone())
            .build()
            .await
            .unwrap();

        assert!(Arc::ptr_eq(endpoint.network().network(), &raw_network));
        assert!(Arc::ptr_eq(
            &raw_network.quic().stun_resolver(),
            &external_resolver
        ));
        assert!(Arc::ptr_eq(&endpoint.resolver(), &endpoint_resolver));
    }

    #[tokio::test]
    async fn owned_default_network_stun_resolver_keeps_h3_resolver_alive_through_weak_edge() {
        let endpoint = Endpoint::builder().build().await.unwrap();
        let stun_resolver = endpoint.network().network().quic().stun_resolver();
        let deferred_any: &dyn Any = stun_resolver.as_ref();
        let deferred = deferred_any
            .downcast_ref::<DeferredStunResolver>()
            .expect("owned network uses a deferred STUN resolver");
        let weak_resolver = deferred
            .get()
            .expect("deferred STUN resolver is initialized");
        let actual = weak_resolver
            .upgrade()
            .expect("DhttpNetwork keeps the STUN resolver target alive");

        assert!(actual.iter().any(|resolver| {
            let resolver_any: &dyn Any = resolver.as_ref();
            resolver_any.is::<H3Resolver<QuicEndpoint>>()
        }));
    }

    #[tokio::test]
    async fn h3_only_endpoint_stun_resolver_uses_h3_final_resolver_not_system_final_resolver() {
        let endpoint = Endpoint::builder()
            .dns(DnsScheme::H3)
            .build()
            .await
            .unwrap();
        let stun_resolver = endpoint.network().network().quic().stun_resolver();
        let deferred_any: &dyn Any = stun_resolver.as_ref();
        let deferred = deferred_any
            .downcast_ref::<DeferredStunResolver>()
            .expect("h3-only endpoint-owned network uses deferred STUN resolver");
        let weak_resolver = deferred
            .get()
            .expect("deferred STUN resolver is initialized");
        let actual = weak_resolver
            .upgrade()
            .expect("DhttpNetwork keeps the STUN resolver target alive");
        let resolver_names = actual
            .iter()
            .map(|resolver| resolver.to_string())
            .collect::<Vec<_>>();

        assert!(
            resolver_names
                .iter()
                .any(|name| name.starts_with("H3 DNS Resolver("))
        );
        assert!(
            !resolver_names
                .iter()
                .any(|name| name == "System DNS Resolver")
        );
    }

    #[tokio::test]
    async fn endpoint_name_returns_dhttp_identity_name() {
        let identity = valid_dhttp_identity("client.example.com.dhttp.net");
        let endpoint = Endpoint::builder()
            .identity(Arc::new(identity))
            .build()
            .await
            .expect("dhttp identity should build endpoint");

        let name = endpoint.name().expect("named endpoint has a dhttp name");

        assert_eq!(name.as_full(), "client.example.com.dhttp.net");
    }

    #[tokio::test]
    async fn request_uri_accepts_str_and_returns_bare_tilde_error_on_first_io() {
        let endpoint = Endpoint::builder().build().await.unwrap();

        let error = match endpoint.get("https://~/api").into_response().await {
            Ok(_) => panic!("bare tilde request should fail before opening a stream"),
            Err(error) => error,
        };

        match error {
            client::RequestError::Build { source } => match source.as_ref() {
                client::RequestBuildError::Uri {
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
            other => panic!("expected request build error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_uri_parse_error_is_returned_on_first_io() {
        let endpoint = Endpoint::builder().build().await.unwrap();

        let error = match endpoint.get("://not a uri").into_response().await {
            Ok(_) => panic!("invalid uri request should fail before opening a stream"),
            Err(error) => error,
        };

        match error {
            client::RequestError::Build { source } => match source.as_ref() {
                client::RequestBuildError::Uri { .. } => {}
                other => panic!("expected request uri conversion error, got {other:?}"),
            },
            other => panic!("expected request build error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authority_only_get_is_rejected_before_connect() {
        let endpoint = Endpoint::builder().build().await.unwrap();
        let uri: http::Uri = "reimu.pilot.dhttp.net".parse().unwrap();

        let error = match endpoint.get(uri).into_response().await {
            Ok(_) => panic!("authority-only GET should fail before opening a stream"),
            Err(error) => error,
        };

        match error {
            client::RequestError::Build { source } => match source.as_ref() {
                client::RequestBuildError::MalformedHeader { source } => {
                    assert!(matches!(
                        source,
                        crate::h3x::qpack::field::MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders {
                            ..
                        }
                    ));
                }
                other => panic!("expected malformed request header error, got {other:?}"),
            },
            other => panic!("expected request build error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_header_setters_after_activation_do_not_replace_first_build_error() {
        let endpoint = Endpoint::builder().build().await.unwrap();
        let request = endpoint.get("https://~/api");

        let first = match request.clone().into_response().await {
            Ok(_) => panic!("bare tilde request should fail before opening a stream"),
            Err(error) => error,
        };
        request.set_method(http::Method::POST);
        request.set_uri("https://example.com/after-activation");
        let second = match request.into_response().await {
            Ok(_) => panic!("cached failed request should not recover after header mutation"),
            Err(error) => error,
        };

        match (&first, &second) {
            (
                client::RequestError::Build {
                    source: first_source,
                },
                client::RequestError::Build {
                    source: second_source,
                },
            ) => assert_eq!(first_source.to_string(), second_source.to_string()),
            other => panic!("expected cached build errors, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn header_mutation_after_activation_is_rejected_without_terminal_message_error() {
        let endpoint = Endpoint::builder().build().await.unwrap();
        let request = endpoint.get("https://~/api");

        let first = match request.clone().into_response().await {
            Ok(_) => panic!("bare tilde request should fail before opening a stream"),
            Err(error) => error,
        };
        request.set_header(
            http::header::HeaderName::from_static("x-after"),
            http::HeaderValue::from_static("activation"),
        );
        let second = match request.into_response().await {
            Ok(_) => panic!("cached failed request should not recover after header mutation"),
            Err(error) => error,
        };

        assert_eq!(first.to_string(), second.to_string());
    }

    #[test]
    fn endpoint_implements_quic_listen() {
        fn assert_listen<T: crate::h3x::quic::Listen>() {}

        assert_listen::<Endpoint>();
    }
}
