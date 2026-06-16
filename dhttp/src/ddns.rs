//! Re-export of the ddns crate APIs used by DHTTP.

use std::{future::Future, sync::Arc};

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
    let final_resolver =
        network_stun_resolver_from_plan(dns_plan, network.clone(), bind, h3_dns_server).await?;

    DhttpNetwork::from_deferred_stun_resolver(network, deferred_stun_resolver, final_resolver)
        .context(build_dhttp_network_with_dns_error::DeferredStunResolverSnafu)
}

#[bon::builder(finish_fn = build)]
pub async fn quic_endpoint_builder_with_dns<F, Fut>(
    #[builder(start_fn)] builder: F,
    #[builder(start_fn)] dns_plan: &DhttpDnsPlan,
    #[builder(default = Arc::<str>::from(resolvers::DHTTP_H3_DNS_SERVER))] h3_dns_server: Arc<str>,
) -> Result<(QuicEndpoint, publishers::Publishers), BuildQuicEndpointWithDnsError>
where
    F: FnOnce(ArcResolver) -> Fut,
    Fut: Future<Output = QuicEndpoint>,
{
    let deferred_endpoint_resolver = Arc::new(DeferredEndpointResolver::new());
    let endpoint_resolver: ArcResolver = deferred_endpoint_resolver.clone();
    let endpoint = builder(endpoint_resolver).await;
    let (final_resolver, publishers) =
        endpoint_dns_from_quic(dns_plan, &endpoint, h3_dns_server).await?;

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
) -> Result<ArcResolvers, BuildDhttpNetworkWithDnsError> {
    let operations = dns_plan.effective_ops();
    let h3_resolver = if uses_h3(&operations) {
        let h3_underlay = network_h3_underlay(&operations, network.clone(), bind.clone()).await?;
        let h3_quic = QuicEndpoint::builder()
            .network(network.clone())
            .resolver(h3_underlay)
            .bind(bind.clone())
            .build()
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
                builder = builder.mdns(network.clone(), bind.clone()).await;
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::System) => {
                builder = builder.system();
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::Http) => {
                builder = builder
                    .http()
                    .expect("BUG: DHTTP HTTP DNS server is a valid URL");
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::H3) => {
                if let Some(h3_resolver) = h3_resolver.clone() {
                    builder = builder.resolver(h3_resolver);
                }
            }
            DhttpDnsOp::Resolver(resolver) => {
                builder = builder.resolver(resolver.clone());
            }
            DhttpDnsOp::Publisher(_) => {}
        }
    }

    network_resolver_chain(builder.build())
}

async fn endpoint_dns_from_quic(
    dns_plan: &DhttpDnsPlan,
    endpoint: &QuicEndpoint,
    h3_dns_server: Arc<str>,
) -> Result<(resolvers::Resolvers, publishers::Publishers), BuildQuicEndpointWithDnsError> {
    let operations = dns_plan.effective_ops();
    let endpoint_h3 = if uses_h3(&operations) {
        let h3_underlay = endpoint_h3_underlay(&operations, endpoint).await?;
        let mut h3_quic = endpoint.clone();
        h3_quic.set_resolver(h3_underlay);
        Some(Arc::new(H3Endpoint::new(h3_quic)))
    } else {
        None
    };

    let mut resolver_builder = resolvers::Resolvers::builder();
    let mut publishers = publishers::Publishers::new();

    for operation in &operations {
        match operation {
            DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns) => {
                let mdns = Arc::new(
                    mdns::MdnsResolvers::bind(
                        endpoint.network().clone(),
                        endpoint.bind_patterns().clone(),
                        resolvers::DHTTP_MDNS_SERVICE,
                    )
                    .await,
                );
                resolver_builder = resolver_builder.resolver(mdns.clone());
                publishers.push(publishers::Publisher::mdns(mdns));
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::System) => {
                resolver_builder = resolver_builder.system();
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::Http) => {
                let http = Arc::new(
                    resolvers::HttpResolver::new(resolvers::DHTTP_HTTP_DNS_SERVER)
                        .expect("BUG: DHTTP HTTP DNS server is a valid URL"),
                );
                resolver_builder = resolver_builder.resolver(http.clone());
                publishers.push(publishers::Publisher::http(http));
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::H3) => {
                let h3_endpoint = endpoint_h3
                    .clone()
                    .expect("BUG: endpoint H3 endpoint exists when H3 DNS is used");
                let h3 = Arc::new(h3_resolver_for_endpoint(
                    h3_dns_server.as_ref(),
                    h3_endpoint,
                )?);
                resolver_builder = resolver_builder.resolver(h3.clone());
                publishers.push(publishers::Publisher::new(
                    publishers::PublishScope::WideArea,
                    h3,
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

    let resolvers = endpoint_resolver_chain(resolver_builder.build())?;
    Ok((resolvers, publishers))
}

async fn endpoint_h3_underlay(
    operations: &[DhttpDnsOp],
    endpoint: &QuicEndpoint,
) -> Result<ArcResolver, BuildQuicEndpointWithDnsError> {
    let resolvers = non_h3_resolvers(
        operations,
        endpoint.network().clone(),
        endpoint.bind_patterns().clone(),
    )
    .await;

    endpoint_arc_resolver_chain(resolvers)
}

async fn network_h3_underlay(
    operations: &[DhttpDnsOp],
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
) -> Result<ArcResolver, BuildDhttpNetworkWithDnsError> {
    let resolvers = non_h3_resolvers(operations, network, bind).await;

    network_arc_resolver_chain(resolvers)
}

async fn non_h3_resolvers(
    operations: &[DhttpDnsOp],
    network: Arc<Network>,
    bind: Arc<Vec<BindPattern>>,
) -> resolvers::Resolvers {
    let mut builder = resolvers::Resolvers::builder();

    for operation in operations {
        match operation {
            DhttpDnsOp::Dns(resolvers::DnsScheme::Mdns) => {
                builder = builder.mdns(network.clone(), bind.clone()).await;
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::System) => {
                builder = builder.system();
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::Http) => {
                builder = builder
                    .http()
                    .expect("BUG: DHTTP HTTP DNS server is a valid URL");
            }
            DhttpDnsOp::Dns(resolvers::DnsScheme::H3) | DhttpDnsOp::Publisher(_) => {}
            DhttpDnsOp::Resolver(resolver) => {
                builder = builder.resolver(resolver.clone());
            }
        }
    }

    if uses_h3(operations) && !has_custom_resolver(operations) && !has_system_dns(operations) {
        builder = builder.system();
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
    h3: Arc<H3Endpoint<QuicEndpoint, crate::dquic::connection::Connection>>,
) -> Result<resolvers::H3Resolver<QuicEndpoint>, BuildQuicEndpointWithDnsError> {
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

fn network_arc_resolver_chain(
    resolvers: resolvers::Resolvers,
) -> Result<ArcResolver, BuildDhttpNetworkWithDnsError> {
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

fn has_custom_resolver(operations: &[DhttpDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, DhttpDnsOp::Resolver(_)))
}

fn has_system_dns(operations: &[DhttpDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, DhttpDnsOp::Dns(resolvers::DnsScheme::System)))
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{
            Arc,
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
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(()) }.boxed()
        }
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
            "DeferredResolver(Resolvers(counting resolver))"
        );
        assert!(publishers.iter().next().is_none());
    }
}
