use std::sync::Arc;

use bon::bon;
use http::Uri;
use http::uri::Authority;

use crate::ddns::DnsScheme;
use crate::ddns::resolvers::{H3Resolver, MdnsResolvers, Resolvers};
use crate::dquic::{
    Identity, Network, QuicEndpoint, binds::BindPattern, client::ClientQuicConfig,
    resolver::Resolve, resolver::handy::SystemResolver, server::ServerQuicConfig,
};
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
    inner: Arc<H3Endpoint<QuicEndpoint>>,
}

impl From<Arc<H3Endpoint<QuicEndpoint>>> for Endpoint {
    fn from(inner: Arc<H3Endpoint<QuicEndpoint>>) -> Self {
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
async fn create_h3_dns_resolver(
    identity: Option<Arc<Identity>>,
    network: Arc<Network>,
    client_config: &ClientQuicConfig,
    bind: Arc<Vec<BindPattern>>,
) -> H3Resolver<QuicEndpoint> {
    let quic = QuicEndpoint::builder()
        .network(network)
        .maybe_identity(identity)
        .client(client_config.clone())
        .bind(bind)
        .build()
        .await;
    let h3 = H3Endpoint::new(quic);
    H3Resolver::new(crate::ddns::DNS_SERVER, h3).expect("BUG: DNS_SERVER is a valid URL")
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

        #[builder(default)] client: ClientQuicConfig,
        #[builder(default)] server: ServerQuicConfig,
        #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
    ) -> Self {
        let network = network.unwrap_or_else(|| {
            Network::builder()
                .stun_server(Arc::<str>::from(STUN_SERVER))
                .build()
        });

        let mut resolvers = Resolvers::new();

        if dns_schemes.contains(&DnsScheme::Mdns) {
            resolvers = resolvers.with(Arc::new(MdnsResolvers::new()));
        }

        if dns_schemes.contains(&DnsScheme::System) {
            resolvers = resolvers.with(Arc::new(SystemResolver));
        }

        if dns_schemes.contains(&DnsScheme::H3) {
            let h3 =
                create_h3_dns_resolver(identity.clone(), network.clone(), &client, bind.clone())
                    .await;
            resolvers = resolvers.with(Arc::new(h3));
        }

        let quic_resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(resolvers);
        let quic = QuicEndpoint::builder()
            .network(network)
            .maybe_identity(identity)
            .resolver(quic_resolver)
            .client(client)
            .server(server)
            .bind(bind)
            .build()
            .await;

        let h3 = H3Endpoint::new(quic);
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
pub enum LoadEndpointError {
    #[snafu(display("failed to locate dhttp home"))]
    NoHome {
        source: crate::home::LocateDhttpHomeError,
    },
    #[snafu(display("failed to load certificate and key"))]
    LoadSsl {
        source: crate::home::identity::ssl::LoadIdentitySslError,
    },
}

impl Endpoint {
    /// Load an endpoint from a domain name.
    ///
    /// Accepts a [`dhttp_identity::DhttpName`], locates the `.dhttp`
    /// home directory, loads the TLS identity from
    /// `~/.dhttp/<name>/ssl/`, and constructs a QUIC endpoint with
    /// [`DnsScheme::H3`], [`DnsScheme::Mdns`], and [`DnsScheme::System`]
    /// DNS resolution schemes and a default network configuration.
    pub async fn load(name: dhttp_identity::DhttpName<'_>) -> Result<Self, LoadEndpointError> {
        use snafu::ResultExt;

        let home = crate::home::DhttpHome::load_from_environment().context(NoHomeSnafu)?;

        let dname = name.into_owned();
        let identity_home = home.identity_home(dname);

        let identity = identity_home.identity().await.context(LoadSslSnafu)?;

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
    pub fn new_request(self: &Arc<Self>) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner.new_request_owned()
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner.new_request_owned().method(Method::GET).uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner.new_request_owned().method(Method::POST).uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner.new_request_owned().method(Method::PUT).uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner
            .new_request_owned()
            .method(Method::DELETE)
            .uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner
            .new_request_owned()
            .method(Method::PATCH)
            .uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner.new_request_owned().method(Method::HEAD).uri(uri)
    }

    /// Convenience method to create an OPTIONS request for `uri`.
    pub fn options(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
        self.inner
            .new_request_owned()
            .method(Method::OPTIONS)
            .uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace(&self, uri: Uri) -> Request<QuicEndpoint, Arc<H3Endpoint<QuicEndpoint>>> {
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
        self: &Arc<Self>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddns::DnsScheme;

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
        let dname = crate::home::identity::DhttpName::parse("invalid_single_label");
        assert!(dname.is_err());
    }

    #[test]
    fn load_valid_name_parses() {
        // Valid multi-label name should parse (may fail at I/O but not at parse)
        let dname = crate::home::identity::DhttpName::parse("reimu.pilot");
        assert!(dname.is_ok());
    }
}
