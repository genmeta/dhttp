//! Re-export of the ddns crate APIs used by DHTTP.

use std::{fmt, future::Future, sync::Arc};

use snafu::ResultExt;

use crate::{
    dquic::{
        Network, QuicEndpoint,
        binds::BindPattern,
        resolver::{Publish, Resolve},
    },
    h3x::endpoint::H3Endpoint,
    network::{ArcResolvers, DeferredStunResolver, DhttpNetwork},
};

pub use ::ddns::*;

/// Resolver trait object used by DHTTP DNS construction.
pub type ArcResolver = Arc<dyn Resolve + Send + Sync>;

/// Publisher trait object used by DHTTP DNS construction.
pub type ArcPublisher = Arc<dyn Publish + Send + Sync>;

const DHTTP_DNS_SUFFIX: &str = "dhttp.net";

#[derive(Clone)]
enum DhttpDnsOp {
    Dns(resolvers::DnsScheme),
    Resolver(ArcResolver),
    Publisher(publishers::Publisher),
}

/// Ordered DNS intent for DHTTP endpoint and network construction.
#[derive(Clone, Default)]
pub struct DhttpDnsPlan {
    ops: Vec<DhttpDnsOp>,
}

impl DhttpDnsPlan {
    /// Create an empty DNS plan.
    ///
    /// Empty plans use DHTTP's default DNS schemes when construction helpers
    /// evaluate them.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a built-in DNS scheme to the plan.
    ///
    /// Built-in schemes are deduplicated by first occurrence when evaluated.
    pub fn push_dns(&mut self, scheme: resolvers::DnsScheme) {
        self.ops.push(DhttpDnsOp::Dns(scheme));
    }

    /// Append a custom resolver to the plan.
    ///
    /// Custom resolvers are not deduplicated.
    pub fn push_resolver(&mut self, resolver: ArcResolver) {
        self.ops.push(DhttpDnsOp::Resolver(resolver));
    }

    /// Append a custom scoped DNS publisher to the plan.
    ///
    /// Custom publishers are not deduplicated.
    pub fn push_publisher(&mut self, scope: publishers::PublishScope, publisher: ArcPublisher) {
        self.ops
            .push(DhttpDnsOp::Publisher(publishers::Publisher::new(
                scope, publisher,
            )));
    }

    fn effective_ops(&self) -> Vec<DhttpDnsOp> {
        let source = if self.ops.is_empty() {
            vec![
                DhttpDnsOp::Dns(resolvers::DnsScheme::H3),
                DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns),
                DhttpDnsOp::Dns(resolvers::DnsScheme::System),
            ]
        } else {
            self.ops.clone()
        };

        let mut seen = std::collections::BTreeSet::new();
        source
            .into_iter()
            .filter(|operation| match operation {
                DhttpDnsOp::Dns(scheme) => seen.insert(*scheme),
                DhttpDnsOp::Resolver(_) | DhttpDnsOp::Publisher(_) => true,
            })
            .collect()
    }

    #[cfg(test)]
    fn effective_dns_schemes_for_test(&self) -> Vec<resolvers::DnsScheme> {
        self.effective_ops()
            .into_iter()
            .filter_map(|operation| match operation {
                DhttpDnsOp::Dns(scheme) => Some(scheme),
                DhttpDnsOp::Resolver(_) | DhttpDnsOp::Publisher(_) => None,
            })
            .collect()
    }

    #[cfg(test)]
    fn effective_ops_len_for_test(&self) -> usize {
        self.effective_ops().len()
    }
}

type DeferredEndpointResolver = resolvers::deferred::DeferredResolver<resolvers::Resolvers>;
type EndpointH3Client = Arc<H3Endpoint<EndpointH3Connector, crate::dquic::connection::Connection>>;

/// Routes DHTTP endpoint names and external authorities to separate scopes.
#[derive(Debug)]
struct DhttpDnsRouter {
    /// Contains only DHTTP-aware and explicitly supplied resolvers.
    dhttp: ArcResolvers,

    /// Contains system, scoped mDNS, and explicitly supplied resolvers.
    external: ArcResolvers,
}

impl fmt::Display for DhttpDnsRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DHTTP DNS Router")
    }
}

impl Resolve for DhttpDnsRouter {
    fn lookup<'a>(&'a self, name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
        if is_dhttp_authority(name) {
            return Resolve::lookup(self.dhttp.as_ref(), name);
        }

        let external = self.external.clone();
        let authority = external_authority(name);
        Box::pin(async move { Resolve::lookup(external.as_ref(), &authority).await })
    }
}

#[derive(Clone)]
struct EndpointH3Clients {
    resolver: EndpointH3Client,
    publisher: EndpointH3Client,
}

#[derive(Clone)]
struct EndpointH3Connector {
    quic: QuicEndpoint,
}

impl EndpointH3Connector {
    fn new(quic: QuicEndpoint) -> Self {
        Self { quic }
    }
}

impl crate::h3x::quic::Connect for EndpointH3Connector {
    type Connection = crate::dquic::connection::Connection;
    type Error = crate::dquic::ConnectError;

    async fn connect(
        &self,
        server: &::http::uri::Authority,
    ) -> Result<Arc<Self::Connection>, Self::Error> {
        crate::h3x::quic::Connect::connect(&self.quic, server).await
    }
}

impl crate::h3x::quic::WithLocalAuthority for EndpointH3Connector {
    type LocalAuthority = crate::dquic::Identity;

    async fn local_authority(
        &self,
    ) -> Result<Option<Self::LocalAuthority>, crate::h3x::quic::ConnectionError> {
        crate::h3x::quic::WithLocalAuthority::local_authority(&self.quic).await
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(build_dhttp_network_with_dns_error))]
pub enum BuildDhttpNetworkWithDnsError {
    #[snafu(display("network dns resolver set is empty"))]
    EmptyResolver,
    #[snafu(display("network deferred stun resolver was already initialized"))]
    DeferredStunResolver {
        source: resolvers::deferred::SetDeferredResolverError,
    },
    #[snafu(display("h3 dns server url is invalid"))]
    InvalidH3DnsServer { source: std::io::Error },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(build_quic_endpoint_with_dns_error))]
pub enum BuildQuicEndpointWithDnsError {
    #[snafu(display("endpoint dns resolver set is empty"))]
    EmptyResolver,
    #[snafu(display("endpoint deferred resolver was already initialized"))]
    DeferredEndpointResolver {
        source: resolvers::deferred::SetDeferredResolverError,
    },
    #[snafu(display("h3 dns server url is invalid"))]
    InvalidH3DnsServer { source: std::io::Error },
}

#[bon::builder(finish_fn = build)]
pub async fn dhttp_network_builder_with_dns<F>(
    #[builder(start_fn)] builder: F,
    #[builder(start_fn)] dns_plan: &DhttpDnsPlan,
    #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
    #[builder(default = Arc::<str>::from(resolvers::DHTTP_H3_DNS_SERVER))] h3_dns_server: Arc<str>,
) -> Result<DhttpNetwork, BuildDhttpNetworkWithDnsError>
where
    F: FnOnce(ArcResolver) -> Arc<Network>,
{
    let deferred_stun_resolver = Arc::new(DeferredStunResolver::new());
    let stun_resolver: ArcResolver = deferred_stun_resolver.clone();
    let network = builder(stun_resolver);
    let mdns_driver = Arc::new(mdns::MdnsBindDriver::new(resolvers::DHTTP_MDNS_SERVICE));
    let final_resolver = network_stun_resolver_from_plan(
        dns_plan,
        network.clone(),
        bind,
        h3_dns_server,
        mdns_driver.clone(),
    )
    .await?;

    DhttpNetwork::from_deferred_stun_resolver(
        network,
        deferred_stun_resolver,
        final_resolver,
        mdns_driver,
    )
    .context(build_dhttp_network_with_dns_error::DeferredStunResolverSnafu)
}

#[bon::builder(finish_fn = build)]
pub async fn quic_endpoint_builder_with_dns<F, Fut>(
    #[builder(start_fn)] builder: F,
    #[builder(start_fn)] dns_plan: &DhttpDnsPlan,
    #[builder(default = Arc::<str>::from(resolvers::DHTTP_H3_DNS_SERVER))] h3_dns_server: Arc<str>,
    #[builder(default = Arc::new(mdns::MdnsBindDriver::new(resolvers::DHTTP_MDNS_SERVICE)))]
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<(QuicEndpoint, publishers::Publishers), BuildQuicEndpointWithDnsError>
where
    F: FnOnce(ArcResolver) -> Fut,
    Fut: Future<Output = QuicEndpoint>,
{
    let deferred_endpoint_resolver = Arc::new(DeferredEndpointResolver::new());
    let endpoint_resolver: ArcResolver = deferred_endpoint_resolver.clone();
    let endpoint = builder(endpoint_resolver).await;
    let (final_resolver, publishers) =
        endpoint_dns_from_quic(dns_plan, &endpoint, h3_dns_server, mdns_driver).await?;

    deferred_endpoint_resolver
        .set(final_resolver)
        .context(build_quic_endpoint_with_dns_error::DeferredEndpointResolverSnafu)?;

    Ok((endpoint, publishers))
}

async fn network_stun_resolver_from_plan(
    dns_plan: &DhttpDnsPlan,
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
    h3_dns_server: Arc<str>,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<ArcResolvers, BuildDhttpNetworkWithDnsError> {
    let operations = dns_plan.effective_ops();
    let shared_mdns = if uses_mdns(&operations) {
        Some(Arc::new(
            mdns::MdnsResolvers::bind_with_driver(
                network.clone(),
                bind.clone(),
                mdns_driver.clone(),
            )
            .await,
        ))
    } else {
        None
    };
    let h3_resolver = if uses_h3(&operations) {
        let h3_underlay = network_h3_underlay(
            &operations,
            network.clone(),
            bind.clone(),
            mdns_driver.clone(),
        )
        .await?;
        let h3_quic =
            dedicated_network_h3_client_quic(network.clone(), bind.clone(), h3_underlay.clone())
                .await;
        Some(Arc::new(h3_resolver_for_network(
            h3_dns_server.as_ref(),
            h3_quic,
        )?))
    } else {
        None
    };

    let mut builder = resolvers::Resolvers::builder();
    for operation in &operations {
        match operation {
            DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns) => {
                let mdns = shared_mdns
                    .clone()
                    .expect("BUG: shared mDNS resolver exists when mDNS is configured");
                builder = builder.candidate_resolver(mdns);
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::System) => {}
            DhttpDnsOp::Dns(resolvers::DnsScheme::Http) => {
                builder = builder
                    .http()
                    .expect("BUG: DHTTP HTTP DNS server is a valid URL");
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::H3) => {
                if let Some(h3_resolver) = h3_resolver.clone() {
                    builder = builder.candidate_resolver(h3_resolver);
                }
            }
            DhttpDnsOp::Resolver(resolver) => {
                builder = builder.resolver(resolver.clone());
            }
            DhttpDnsOp::Publisher(_) => {}
        }
    }

    let dhttp_resolvers = network_resolver_chain(builder.build())?;
    let external_resolvers =
        network_resolver_chain(external_resolvers_from_shared(&operations, shared_mdns))?;

    let router: ArcResolver = Arc::new(DhttpDnsRouter {
        dhttp: dhttp_resolvers,
        external: external_resolvers,
    });
    network_resolver_chain(resolvers::Resolvers::new().with(router))
}

async fn endpoint_dns_from_quic(
    dns_plan: &DhttpDnsPlan,
    endpoint: &QuicEndpoint,
    h3_dns_server: Arc<str>,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<(resolvers::Resolvers, publishers::Publishers), BuildQuicEndpointWithDnsError> {
    let operations = dns_plan.effective_ops();
    let endpoint_h3 = if uses_h3(&operations) {
        Some(endpoint_h3_clients_from_quic(&operations, endpoint, mdns_driver.clone()).await?)
    } else {
        None
    };
    let shared_mdns = if uses_mdns(&operations) {
        Some(Arc::new(
            mdns::MdnsResolvers::bind_with_driver(
                endpoint.network().clone(),
                endpoint.bind_patterns().clone(),
                mdns_driver.clone(),
            )
            .await,
        ))
    } else {
        None
    };

    let mut resolver_builder = resolvers::Resolvers::builder();
    let mut publishers = publishers::Publishers::new();

    for operation in &operations {
        match operation {
            DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns) => {
                let mdns = shared_mdns
                    .clone()
                    .expect("BUG: shared mDNS resolver exists when mDNS is configured");
                resolver_builder = resolver_builder.candidate_resolver(mdns.clone());
                publishers.push(publishers::Publisher::mdns(
                    mdns,
                    Arc::new(endpoint.clone()),
                ));
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::System) => {}
            DhttpDnsOp::Dns(resolvers::DnsScheme::Http) => {
                let http = Arc::new(
                    resolvers::HttpResolver::new(crate::endpoint::BOOTSTRAP_URL)
                        .expect("BUG: DHTTP HTTP DNS server is a valid URL"),
                );
                resolver_builder = resolver_builder.candidate_resolver(http.clone());
                publishers.push(publishers::Publisher::http(http));
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::H3) => {
                let h3_endpoint = endpoint_h3
                    .clone()
                    .expect("BUG: endpoint H3 endpoint exists when H3 DNS is used");
                let h3_resolver = Arc::new(h3_resolver_for_endpoint(
                    h3_dns_server.as_ref(),
                    h3_endpoint.resolver,
                )?);
                let h3_publisher = Arc::new(h3_resolver_for_endpoint(
                    h3_dns_server.as_ref(),
                    h3_endpoint.publisher,
                )?);
                resolver_builder = resolver_builder.candidate_resolver(h3_resolver);
                publishers.push(publishers::Publisher::new(
                    publishers::PublishScope::WideArea,
                    h3_publisher,
                ));
            }
            DhttpDnsOp::Resolver(resolver) => {
                resolver_builder = resolver_builder.resolver(resolver.clone());
            }
            DhttpDnsOp::Publisher(publisher) => {
                publishers.push(publisher.clone());
            }
        }
    }

    let dhttp = endpoint_resolver_chain(resolver_builder.build())?;
    let external = external_resolvers_from_shared(&operations, shared_mdns);
    let router: ArcResolver = Arc::new(DhttpDnsRouter {
        dhttp: Arc::new(dhttp),
        external: Arc::new(external),
    });
    let resolvers = endpoint_resolver_chain(resolvers::Resolvers::new().with(router))?;
    Ok((resolvers, publishers))
}

async fn endpoint_h3_clients_from_quic(
    operations: &[DhttpDnsOp],
    endpoint: &QuicEndpoint,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<EndpointH3Clients, BuildQuicEndpointWithDnsError> {
    let h3_underlay = endpoint_h3_underlay(operations, endpoint, mdns_driver).await?;
    let resolver_quic = dedicated_h3_client_quic(endpoint, h3_underlay.clone()).await;
    let publisher_quic = dedicated_h3_client_quic(endpoint, h3_underlay).await;

    Ok(EndpointH3Clients {
        // Endpoint-facing DNS resolution and publication can run concurrently
        // while the endpoint is also serving traffic. Keep separate H3 pools
        // and dedicated QUIC endpoints. The H3 DNS clients must always use
        // DHTTP's H3-capable trust/ALPN defaults instead of inheriting an
        // arbitrary serving endpoint transport config; callers such as pishoo
        // may construct the serving QUIC endpoint directly and omit H3 ALPNs.
        // Preserve the serving identity so authenticated H3 DNS publish can
        // still sign requests and present client certificates.
        resolver: Arc::new(H3Endpoint::new(EndpointH3Connector::new(resolver_quic))),
        publisher: Arc::new(H3Endpoint::new(EndpointH3Connector::new(publisher_quic))),
    })
}

async fn dedicated_h3_client_quic(endpoint: &QuicEndpoint, resolver: ArcResolver) -> QuicEndpoint {
    QuicEndpoint::builder()
        .network(endpoint.network().clone())
        .maybe_identity(endpoint.identity())
        .resolver(resolver)
        .client(crate::trust::default_client_quic_config())
        .server(crate::trust::default_server_quic_config())
        .bind(endpoint.bind_patterns().clone())
        .build()
        .await
}

async fn dedicated_network_h3_client_quic(
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
    resolver: ArcResolver,
) -> QuicEndpoint {
    QuicEndpoint::builder()
        .network(network)
        .resolver(resolver)
        .client(crate::trust::default_client_quic_config())
        .server(crate::trust::default_server_quic_config())
        .bind(bind)
        .build()
        .await
}

async fn endpoint_h3_underlay(
    operations: &[DhttpDnsOp],
    endpoint: &QuicEndpoint,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<ArcResolver, BuildQuicEndpointWithDnsError> {
    let resolvers = external_resolvers(
        operations,
        endpoint.network().clone(),
        endpoint.bind_patterns().clone(),
        mdns_driver,
    )
    .await;

    endpoint_arc_resolver_chain(resolvers)
}

async fn network_h3_underlay(
    operations: &[DhttpDnsOp],
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> Result<ArcResolvers, BuildDhttpNetworkWithDnsError> {
    let resolvers = external_resolvers(operations, network, bind, mdns_driver).await;

    network_resolver_chain(resolvers)
}

/// Build the external resolver scope used by bootstrap and normal authorities.
async fn external_resolvers(
    operations: &[DhttpDnsOp],
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
    mdns_driver: Arc<mdns::MdnsBindDriver>,
) -> resolvers::Resolvers {
    let shared_mdns = if uses_mdns(operations) {
        Some(Arc::new(
            mdns::MdnsResolvers::bind_with_driver(network, bind, mdns_driver).await,
        ))
    } else {
        None
    };
    external_resolvers_from_shared(operations, shared_mdns)
}

/// Build an external resolver scope around an already-shared mDNS view.
fn external_resolvers_from_shared(
    operations: &[DhttpDnsOp],
    shared_mdns: Option<Arc<mdns::MdnsResolvers>>,
) -> resolvers::Resolvers {
    let mut builder = resolvers::Resolvers::builder().system();

    for operation in operations {
        match operation {
            DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns) => {
                let mdns = shared_mdns
                    .clone()
                    .expect("BUG: shared mDNS resolver exists when mDNS is configured");
                builder = builder.candidate_resolver(mdns);
            }
            DhttpDnsOp::Dns(
                resolvers::DnsScheme::System
                | resolvers::DnsScheme::Http
                | resolvers::DnsScheme::H3,
            )
            | DhttpDnsOp::Publisher(_) => {}
            DhttpDnsOp::Resolver(resolver) => {
                builder = builder.resolver(resolver.clone());
            }
        }
    }

    builder.build()
}

fn h3_resolver_for_network(
    h3_dns_server: &str,
    quic: QuicEndpoint,
) -> Result<resolvers::H3Resolver<QuicEndpoint>, BuildDhttpNetworkWithDnsError> {
    let h3 = Arc::new(H3Endpoint::new(quic));
    resolvers::H3Resolver::from_endpoint(h3_dns_server, h3)
        .context(build_dhttp_network_with_dns_error::InvalidH3DnsServerSnafu)
}

fn h3_resolver_for_endpoint(
    h3_dns_server: &str,
    h3: EndpointH3Client,
) -> Result<resolvers::H3Resolver<EndpointH3Connector>, BuildQuicEndpointWithDnsError> {
    resolvers::H3Resolver::from_endpoint(h3_dns_server, h3)
        .context(build_quic_endpoint_with_dns_error::InvalidH3DnsServerSnafu)
}

fn endpoint_resolver_chain(
    resolvers: resolvers::Resolvers,
) -> Result<resolvers::Resolvers, BuildQuicEndpointWithDnsError> {
    if resolvers.iter().next().is_none() {
        build_quic_endpoint_with_dns_error::EmptyResolverSnafu.fail()
    } else {
        Ok(resolvers)
    }
}

fn endpoint_arc_resolver_chain(
    resolvers: resolvers::Resolvers,
) -> Result<ArcResolver, BuildQuicEndpointWithDnsError> {
    if resolvers.iter().next().is_none() {
        build_quic_endpoint_with_dns_error::EmptyResolverSnafu.fail()
    } else {
        Ok(Arc::new(resolvers))
    }
}

fn network_resolver_chain(
    resolvers: resolvers::Resolvers,
) -> Result<ArcResolvers, BuildDhttpNetworkWithDnsError> {
    if resolvers.iter().next().is_none() {
        build_dhttp_network_with_dns_error::EmptyResolverSnafu.fail()
    } else {
        Ok(Arc::new(resolvers))
    }
}

fn uses_h3(operations: &[DhttpDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, DhttpDnsOp::Dns(resolvers::DnsScheme::H3)))
}

/// Return whether the plan requires an mDNS resolver view.
fn uses_mdns(operations: &[DhttpDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns)))
}

/// Classify a validated authority by host without interpreting its port as a sequence.
fn is_dhttp_authority(name: &str) -> bool {
    let host = match name.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
        {
            host
        }
        _ => name,
    };
    let host = host.strip_suffix('.').unwrap_or(host);

    if rustls::pki_types::DnsName::try_from(host).is_err() {
        return false;
    }

    if host.eq_ignore_ascii_case(DHTTP_DNS_SUFFIX) {
        return true;
    }

    let Some(suffix_start) = host.len().checked_sub(DHTTP_DNS_SUFFIX.len()) else {
        return false;
    };
    suffix_start > 0
        && host.as_bytes().get(suffix_start - 1) == Some(&b'.')
        && host.as_bytes()[suffix_start..].eq_ignore_ascii_case(DHTTP_DNS_SUFFIX.as_bytes())
}

/// Add port 443 to an external authority only when it has no explicit port.
fn external_authority(name: &str) -> String {
    let Ok(authority) = name.parse::<::http::uri::Authority>() else {
        return name.to_owned();
    };
    if name.rsplit_once(':').is_some_and(|(host, digits)| {
        !host.is_empty() && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
    }) {
        return name.to_owned();
    }

    format!("{authority}:443")
}

pub(crate) fn uses_h3_dns(name: &str) -> bool {
    is_dhttp_authority(name)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::{
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use futures::{FutureExt, StreamExt, stream};

    use super::*;
    use crate::dquic::resolver::{Publish, PublishFuture, Resolve};

    #[derive(Debug)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }

    impl fmt::Display for CountingResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("counting resolver")
        }
    }

    impl Resolve for CountingResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    #[derive(Debug, Default)]
    struct RecordingResolver {
        names: Mutex<Vec<String>>,
    }

    impl fmt::Display for RecordingResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("recording resolver")
        }
    }

    impl Resolve for RecordingResolver {
        fn lookup<'a>(&'a self, name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
            self.names
                .lock()
                .expect("resolver names lock poisoned")
                .push(name.to_owned());
            async move { Ok(stream::empty().boxed()) }.boxed()
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

    impl Publish for CountingPublisher {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            _endpoints: &mut dyn Iterator<Item = crate::dquic::net::EndpointAddr>,
        ) -> PublishFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(()) }.boxed()
        }
    }

    #[test]
    fn h3_dns_is_limited_to_dhttp_names() {
        for name in [
            "dhttp.net",
            "DHTTP.NET.",
            "node.dhttp.net",
            "deep.node.dhttp.net:2",
            "deep.node.dhttp.net.:7",
        ] {
            assert!(uses_h3_dns(name), "expected H3 DNS for {name}");
        }

        for name in [
            "nat.genmeta.net:20004",
            "ddns.genmeta.net:443",
            "notdhttp.net",
            "dhttp.net.example",
            "127.0.0.1:443",
            "[::1]:443",
            "dhttp.net:service",
            "bad..name.dhttp.net",
        ] {
            assert!(!uses_h3_dns(name), "unexpected H3 DNS for {name}");
        }
    }

    #[tokio::test]
    async fn stun_resolver_router_selects_branch_from_lookup_name() {
        let dhttp_calls = Arc::new(AtomicUsize::new(0));
        let external_calls = Arc::new(AtomicUsize::new(0));
        let dhttp = Arc::new(resolvers::Resolvers::new().with(Arc::new(CountingResolver {
            calls: dhttp_calls.clone(),
        })));
        let external = Arc::new(resolvers::Resolvers::new().with(Arc::new(CountingResolver {
            calls: external_calls.clone(),
        })));
        let router = DhttpDnsRouter { dhttp, external };

        let _dhttp_records = router
            .lookup("node.dhttp.net")
            .await
            .expect("dhttp STUN name should use dhttp resolvers");
        assert_eq!(dhttp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(external_calls.load(Ordering::SeqCst), 0);

        let _external_records = router
            .lookup("nat.genmeta.net:20004")
            .await
            .expect("external STUN name should use external resolvers");
        assert_eq!(dhttp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(external_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn router_preserves_dhttp_authorities_and_defaults_external_ports() {
        let dhttp = Arc::new(RecordingResolver::default());
        let external = Arc::new(RecordingResolver::default());
        let router = DhttpDnsRouter {
            dhttp: Arc::new(resolvers::Resolvers::new().with(dhttp.clone())),
            external: Arc::new(resolvers::Resolvers::new().with(external.clone())),
        };

        for name in ["node.dhttp.net", "node.dhttp.net:2"] {
            let _records = router.lookup(name).await.expect("DHTTP lookup succeeds");
        }
        for name in [
            "nat.genmeta.net",
            "nat.genmeta.net:20004",
            "nat.genmeta.net:65536",
            "printer.local",
            "[::1]",
        ] {
            let _records = router.lookup(name).await.expect("external lookup succeeds");
        }

        assert_eq!(
            *dhttp.names.lock().expect("resolver names lock poisoned"),
            ["node.dhttp.net", "node.dhttp.net:2"]
        );
        assert_eq!(
            *external.names.lock().expect("resolver names lock poisoned"),
            [
                "nat.genmeta.net:443",
                "nat.genmeta.net:20004",
                "nat.genmeta.net:65536",
                "printer.local:443",
                "[::1]:443",
            ]
        );
    }

    #[test]
    fn dhttp_dns_plan_defaults_only_when_empty() {
        let empty = DhttpDnsPlan::new();

        assert_eq!(
            empty.effective_dns_schemes_for_test(),
            vec![
                resolvers::DnsScheme::H3,
                resolvers::DnsScheme::Mdns,
                resolvers::DnsScheme::System,
            ]
        );

        let mut explicit = DhttpDnsPlan::new();
        explicit.push_resolver(Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        }));

        assert!(explicit.effective_dns_schemes_for_test().is_empty());
    }

    #[test]
    fn dhttp_dns_plan_deduplicates_dns_schemes_not_custom_ops() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver { calls });
        let publisher: Arc<dyn Publish + Send + Sync> = Arc::new(CountingPublisher {
            calls: Arc::new(AtomicUsize::new(0)),
        });

        let mut plan = DhttpDnsPlan::new();
        plan.push_dns(resolvers::DnsScheme::System);
        plan.push_resolver(resolver.clone());
        plan.push_dns(resolvers::DnsScheme::System);
        plan.push_resolver(resolver);
        plan.push_publisher(publishers::PublishScope::WideArea, publisher.clone());
        plan.push_publisher(publishers::PublishScope::WideArea, publisher);

        assert_eq!(plan.effective_ops_len_for_test(), 5);
    }

    #[tokio::test]
    async fn dhttp_network_builder_with_dns_passes_deferred_resolver_to_builder() {
        let mut plan = DhttpDnsPlan::new();
        plan.push_resolver(Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        }));

        let network = dhttp_network_builder_with_dns(
            |resolver| {
                assert!(resolver.to_string().starts_with("DeferredResolver("));
                crate::dquic::Network::builder()
                    .stun_resolver(resolver)
                    .build()
            },
            &plan,
        )
        .build()
        .await
        .expect("network helper should build");

        assert!(
            network
                .network()
                .quic()
                .stun_resolver()
                .to_string()
                .starts_with("DeferredResolver(")
        );
    }

    #[tokio::test]
    async fn quic_endpoint_builder_with_dns_returns_endpoint_and_publishers() {
        let mut plan = DhttpDnsPlan::new();
        plan.push_resolver(Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        }));

        let (endpoint, publishers) = quic_endpoint_builder_with_dns(
            |resolver| async move {
                crate::dquic::QuicEndpoint::builder()
                    .resolver(resolver)
                    .build()
                    .await
            },
            &plan,
        )
        .build()
        .await
        .expect("endpoint helper should build");

        assert_eq!(
            endpoint.resolver().to_string(),
            "DeferredResolver(Resolvers(DHTTP DNS Router))"
        );
        assert!(publishers.iter().next().is_none());
    }

    #[tokio::test]
    async fn named_mdns_endpoint_builds_identity_owned_publisher() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        fn assert_dynamic_authority<T: h3x::quic::DynWithLocalAuthority>() {}
        assert_dynamic_authority::<QuicEndpoint>();

        fn publication_loop(
            name: dhttp_identity::name::Name<'static>,
            publishers: publishers::Publishers,
            source: publishers::EndpointBindingAddresses,
        ) -> publishers::EndpointPublicationLoop<publishers::EndpointBindingAddresses> {
            publishers::EndpointPublicationLoop::new(name, publishers, source)
        }

        let identity = Arc::new(crate::dquic::Identity::new(
            "client.example.com.dhttp.net".parse().unwrap(),
            vec![CertificateDer::from(
                include_bytes!("../../identity/tests/fixtures/valid.der").to_vec(),
            )],
            PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
        ));
        let mut plan = DhttpDnsPlan::new();
        plan.push_dns(resolvers::DnsScheme::Mdns);

        let (endpoint, publishers) = quic_endpoint_builder_with_dns(
            |resolver| async move {
                crate::dquic::QuicEndpoint::builder()
                    .identity(identity)
                    .resolver(resolver)
                    .build()
                    .await
            },
            &plan,
        )
        .build()
        .await
        .expect("named mDNS endpoint should build");

        assert_eq!(publishers.iter().count(), 1);
        let source = publishers::EndpointBindingAddresses::new(
            endpoint.network().clone(),
            endpoint.bind_patterns().clone(),
        );
        let _loop = publication_loop(
            "client.example.com.dhttp.net".parse().unwrap(),
            publishers,
            source,
        );
    }

    #[tokio::test]
    async fn endpoint_h3_dns_clients_split_resolver_and_publisher_connectors() {
        let endpoint = crate::dquic::QuicEndpoint::builder().build().await;
        let operations = vec![DhttpDnsOp::Dns(resolvers::DnsScheme::H3)];
        let mut source_quic = endpoint.clone();
        let source_client = (*source_quic.client_config_mut()).clone();
        let source_server = (*source_quic.server_config_mut()).clone();

        let clients = endpoint_h3_clients_from_quic(
            &operations,
            &endpoint,
            Arc::new(mdns::MdnsBindDriver::new(resolvers::DHTTP_MDNS_SERVICE)),
        )
        .await
        .expect("h3 dns clients should build");

        assert!(
            !Arc::ptr_eq(&clients.resolver, &clients.publisher),
            "resolver and publisher must not share the same H3 endpoint pool"
        );
        assert!(
            Arc::ptr_eq(clients.resolver.quic().quic.network(), endpoint.network()),
            "resolver h3 dns client should stay on the serving endpoint network"
        );
        assert!(
            Arc::ptr_eq(clients.publisher.quic().quic.network(), endpoint.network()),
            "publisher h3 dns client should stay on the serving endpoint network"
        );

        let mut resolver_quic = clients.resolver.quic().quic.clone();
        let resolver_client = (*resolver_quic.client_config_mut()).clone();
        let resolver_server = (*resolver_quic.server_config_mut()).clone();
        let mut publisher_quic = clients.publisher.quic().quic.clone();
        let publisher_client = (*publisher_quic.client_config_mut()).clone();
        let publisher_server = (*publisher_quic.server_config_mut()).clone();

        assert_eq!(resolver_client, crate::trust::default_client_quic_config());
        assert_eq!(publisher_client, crate::trust::default_client_quic_config());
        assert_eq!(resolver_server, crate::trust::default_server_quic_config());
        assert_eq!(publisher_server, crate::trust::default_server_quic_config());
        assert!(
            source_client.alpns.is_empty() && source_server.alpns.is_empty(),
            "test source endpoint should keep the raw quic defaults so dedicated H3 DNS clients prove they install DHTTP H3 defaults independently"
        );
        assert!(
            Arc::ptr_eq(
                clients.resolver.quic().quic.resolver(),
                clients.publisher.quic().quic.resolver()
            ),
            "resolver and publisher h3 dns clients should share the same dedicated underlay resolver chain"
        );
        assert!(
            !Arc::ptr_eq(
                clients.publisher.quic().quic.resolver(),
                endpoint.resolver()
            ),
            "publisher h3 dns client should override the serving endpoint resolver with the dedicated underlay resolver"
        );
    }

    #[tokio::test]
    async fn network_h3_stun_resolver_quic_uses_dhttp_h3_defaults() {
        let network = crate::dquic::Network::builder().build();
        let bind = Arc::new(vec![
            crate::dquic::binds::BindPattern::from_str("*")
                .expect("wildcard bind pattern should parse"),
        ]);
        let operations = vec![DhttpDnsOp::Dns(resolvers::DnsScheme::H3)];
        let h3_underlay = network_h3_underlay(
            &operations,
            network.clone(),
            bind.clone(),
            Arc::new(mdns::MdnsBindDriver::new(resolvers::DHTTP_MDNS_SERVICE)),
        )
        .await
        .expect("network h3 underlay should build");

        let mut quic = dedicated_network_h3_client_quic(network, bind, h3_underlay).await;

        assert_eq!(
            (*quic.client_config_mut()).clone(),
            crate::trust::default_client_quic_config()
        );
        assert_eq!(
            (*quic.server_config_mut()).clone(),
            crate::trust::default_server_quic_config()
        );
    }
}
