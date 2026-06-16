use std::{ops::Deref, sync::Arc};

use snafu::Snafu;

use crate::ddns::{
    mdns::MdnsResolvers,
    publishers::{PublishScope, Publisher, Publishers},
    resolvers::{
        DHTTP_HTTP_DNS_SERVER, DHTTP_MDNS_SERVICE, DnsScheme, H3Resolver, HttpResolver, Resolvers,
        deferred::DeferredResolver, weak::WeakResolver,
    },
};
use crate::dquic::{
    Network, QuicEndpoint,
    binds::BindPattern,
    net::{Devices, InterfaceManager, Locations, ProductIO, QuicRouter, handy::DEFAULT_IO_FACTORY},
    resolver::{Publish, Resolve, handy::SystemResolver},
};

pub(crate) type DynResolver = dyn Resolve + Send + Sync;
pub(crate) type ArcResolver = Arc<DynResolver>;
pub(crate) type DeferredStunResolver = DeferredResolver<WeakResolver<Resolvers>>;
pub(crate) type DeferredEndpointH3Resolver = DeferredResolver<H3Resolver<QuicEndpoint>>;
pub(crate) type ArcEndpointH3Resolver = Arc<DeferredEndpointH3Resolver>;
pub(crate) type DynPublisher = dyn Publish + Send + Sync;
pub(crate) type ArcPublisher = Arc<DynPublisher>;
pub(crate) type ArcResolvers = Arc<Resolvers>;

#[derive(Debug, Snafu)]
#[snafu(module(build_endpoint_dns_error))]
pub enum BuildEndpointDnsError {
    #[snafu(display("endpoint dns resolver set is empty"))]
    EmptyResolver,
}

#[derive(Debug, Snafu)]
#[snafu(module(build_stun_dns_error))]
pub enum BuildStunDnsError {
    #[snafu(display("stun dns resolver set is empty"))]
    EmptyResolver,
}

#[derive(Clone)]
pub(crate) enum EndpointDnsOp {
    Dns(DnsScheme),
    Resolver(ArcResolver),
    Publisher(Publisher),
}

#[derive(Clone, Default)]
pub(crate) struct EndpointDnsPlan {
    ops: Vec<EndpointDnsOp>,
}

#[derive(Debug)]
pub(crate) struct BuiltEndpointDns {
    pub(crate) endpoint_resolver: ArcResolver,
    pub(crate) endpoint_publishers: Publishers,
    pub(crate) endpoint_h3_deferred: Option<ArcEndpointH3Resolver>,
    pub(crate) endpoint_h3_underlay: ArcResolver,
}

impl EndpointDnsPlan {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_dns(mut self, scheme: DnsScheme) -> Self {
        self.push_dns(scheme);
        self
    }

    pub(crate) fn with_resolver(mut self, resolver: ArcResolver) -> Self {
        self.push_resolver(resolver);
        self
    }

    pub(crate) fn with_publisher(mut self, scope: PublishScope, publisher: ArcPublisher) -> Self {
        self.push_publisher(scope, publisher);
        self
    }

    pub(crate) fn push_dns(&mut self, scheme: DnsScheme) {
        self.ops.push(EndpointDnsOp::Dns(scheme));
    }

    pub(crate) fn push_resolver(&mut self, resolver: ArcResolver) {
        self.ops.push(EndpointDnsOp::Resolver(resolver));
    }

    pub(crate) fn push_publisher(&mut self, scope: PublishScope, publisher: ArcPublisher) {
        self.ops
            .push(EndpointDnsOp::Publisher(Publisher::new(scope, publisher)));
    }

    fn effective_ops(&self) -> Vec<EndpointDnsOp> {
        let source = if self.ops.is_empty() {
            vec![
                EndpointDnsOp::Dns(DnsScheme::H3),
                EndpointDnsOp::Dns(DnsScheme::Mdns),
                EndpointDnsOp::Dns(DnsScheme::System),
            ]
        } else {
            self.ops.clone()
        };

        let mut seen = std::collections::BTreeSet::new();
        source
            .into_iter()
            .filter(|operation| match operation {
                EndpointDnsOp::Dns(scheme) => seen.insert(*scheme),
                EndpointDnsOp::Resolver(_) | EndpointDnsOp::Publisher(_) => true,
            })
            .collect()
    }

    pub(crate) fn uses_h3(&self) -> bool {
        self.effective_ops()
            .iter()
            .any(|operation| matches!(operation, EndpointDnsOp::Dns(DnsScheme::H3)))
    }

    pub(crate) async fn build_endpoint_dns(
        &self,
        network: Arc<Network>,
        bind: Arc<Vec<BindPattern>>,
    ) -> Result<BuiltEndpointDns, BuildEndpointDnsError> {
        let operations = self.effective_ops();
        let mut resolver_builder = Resolvers::builder();
        let mut publishers = Publishers::new();
        let mut endpoint_h3_deferred = None;

        for operation in &operations {
            match operation {
                EndpointDnsOp::Dns(DnsScheme::Mdns) => {
                    let mdns = Arc::new(
                        MdnsResolvers::bind(network.clone(), bind.clone(), DHTTP_MDNS_SERVICE)
                            .await,
                    );
                    resolver_builder = resolver_builder.resolver(mdns.clone());
                    publishers.push(Publisher::mdns(mdns));
                }
                EndpointDnsOp::Dns(DnsScheme::System) => {
                    resolver_builder = resolver_builder.system();
                }
                EndpointDnsOp::Dns(DnsScheme::Http) => {
                    let http = Arc::new(
                        HttpResolver::new(DHTTP_HTTP_DNS_SERVER)
                            .expect("BUG: DHTTP HTTP DNS server is a valid URL"),
                    );
                    resolver_builder = resolver_builder.resolver(http.clone());
                    publishers.push(Publisher::http(http));
                }
                EndpointDnsOp::Dns(DnsScheme::H3) => {
                    let h3 = Arc::new(DeferredEndpointH3Resolver::new());
                    resolver_builder = resolver_builder.resolver(h3.clone());
                    publishers.push(Publisher::new(PublishScope::WideArea, h3.clone()));
                    endpoint_h3_deferred = Some(h3);
                }
                EndpointDnsOp::Resolver(resolver) => {
                    resolver_builder = resolver_builder.resolver(resolver.clone());
                }
                EndpointDnsOp::Publisher(publisher) => {
                    publishers.push(publisher.clone());
                }
            }
        }

        let endpoint_resolver = endpoint_resolver_chain(resolver_builder.build())?;
        let endpoint_h3_underlay = self.build_endpoint_h3_underlay(network, bind).await?;

        Ok(BuiltEndpointDns {
            endpoint_resolver,
            endpoint_publishers: publishers,
            endpoint_h3_deferred,
            endpoint_h3_underlay,
        })
    }

    async fn build_endpoint_h3_underlay(
        &self,
        network: Arc<Network>,
        bind: Arc<Vec<BindPattern>>,
    ) -> Result<ArcResolver, BuildEndpointDnsError> {
        let operations = self.effective_ops();
        let mut builder = Resolvers::builder();

        for operation in &operations {
            match operation {
                EndpointDnsOp::Dns(DnsScheme::Mdns) => {
                    builder = builder.mdns(network.clone(), bind.clone()).await;
                }
                EndpointDnsOp::Dns(DnsScheme::System) => {
                    builder = builder.system();
                }
                EndpointDnsOp::Dns(DnsScheme::Http) => {
                    builder = builder
                        .http()
                        .expect("BUG: DHTTP HTTP DNS server is a valid URL");
                }
                EndpointDnsOp::Dns(DnsScheme::H3) | EndpointDnsOp::Publisher(_) => {}
                EndpointDnsOp::Resolver(resolver) => {
                    builder = builder.resolver(resolver.clone());
                }
            }
        }

        if self.uses_h3() && !has_custom_resolver(&operations) && !has_system_dns(&operations) {
            builder = builder.system();
        }

        endpoint_resolver_chain(builder.build())
    }

    pub(crate) async fn build_stun_dns(
        &self,
        h3_resolver: Option<ArcResolver>,
        network: Arc<Network>,
        bind: Arc<Vec<BindPattern>>,
    ) -> Result<ArcResolvers, BuildStunDnsError> {
        let operations = self.effective_ops();
        let mut builder = Resolvers::builder();

        for operation in &operations {
            match operation {
                EndpointDnsOp::Dns(DnsScheme::Mdns) => {
                    builder = builder.mdns(network.clone(), bind.clone()).await;
                }
                EndpointDnsOp::Dns(DnsScheme::System) => {
                    builder = builder.system();
                }
                EndpointDnsOp::Dns(DnsScheme::Http) => {
                    builder = builder
                        .http()
                        .expect("BUG: DHTTP HTTP DNS server is a valid URL");
                }
                EndpointDnsOp::Dns(DnsScheme::H3) => {
                    if let Some(h3_resolver) = h3_resolver.clone() {
                        builder = builder.resolver(h3_resolver);
                    }
                }
                EndpointDnsOp::Resolver(resolver) => {
                    builder = builder.resolver(resolver.clone());
                }
                EndpointDnsOp::Publisher(_) => {}
            }
        }

        stun_resolver_chain(builder.build())
    }
}

fn endpoint_resolver_chain(resolvers: Resolvers) -> Result<ArcResolver, BuildEndpointDnsError> {
    if resolvers.iter().next().is_none() {
        build_endpoint_dns_error::EmptyResolverSnafu.fail()
    } else {
        Ok(Arc::new(resolvers))
    }
}

fn stun_resolver_chain(resolvers: Resolvers) -> Result<ArcResolvers, BuildStunDnsError> {
    if resolvers.iter().next().is_none() {
        build_stun_dns_error::EmptyResolverSnafu.fail()
    } else {
        Ok(Arc::new(resolvers))
    }
}

fn has_custom_resolver(operations: &[EndpointDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, EndpointDnsOp::Resolver(_)))
}

fn has_system_dns(operations: &[EndpointDnsOp]) -> bool {
    operations
        .iter()
        .any(|operation| matches!(operation, EndpointDnsOp::Dns(DnsScheme::System)))
}


#[derive(Clone)]
pub(crate) struct ResolverPlan {
    schemes: Vec<DnsScheme>,
    custom: Option<ArcResolver>,
}

impl ResolverPlan {
    pub(crate) fn new(schemes: Vec<DnsScheme>, custom: Option<ArcResolver>) -> Self {
        let schemes = if schemes.is_empty() && custom.is_none() {
            vec![DnsScheme::H3, DnsScheme::Mdns, DnsScheme::System]
        } else {
            schemes
        };
        Self { schemes, custom }
    }

    pub(crate) fn select_resolver(&self, resolvers: Resolvers) -> ArcResolver {
        if self.schemes.is_empty()
            && let Some(custom) = self.custom.clone()
        {
            custom
        } else {
            Arc::new(resolvers)
        }
    }

    pub(crate) fn final_resolver(&self, resolvers: Resolvers) -> ArcResolver {
        self.select_resolver(resolvers)
    }
}

#[derive(Clone)]
pub struct DhttpNetwork {
    network: Arc<Network>,
    deferred_stun_resolver: Option<Arc<DeferredStunResolver>>,
    _stun_resolver: Option<ArcResolver>,
}

impl DhttpNetwork {
    #[must_use]
    pub fn network(&self) -> &Arc<Network> {
        &self.network
    }

    pub(crate) fn finish_stun_resolver(&mut self, stun_resolver: ArcResolvers) {
        let Some(deferred) = self.deferred_stun_resolver.clone() else {
            return;
        };
        deferred
            .set(WeakResolver::new(Arc::downgrade(&stun_resolver)))
            .expect("BUG: network STUN resolver is set exactly once");
        let keepalive: ArcResolver = stun_resolver;
        self._stun_resolver = Some(keepalive);
    }

    pub(crate) fn endpoint_owned() -> Self {
        let deferred = Arc::new(DeferredStunResolver::new());
        let stun_resolver: ArcResolver = deferred.clone();
        let network = Network::builder()
            .maybe_stun_server(Some(Arc::<str>::from(crate::endpoint::STUN_SERVER)))
            .stun_resolver(stun_resolver)
            .build();
        Self {
            network,
            deferred_stun_resolver: Some(deferred),
            _stun_resolver: None,
        }
    }
}

impl Deref for DhttpNetwork {
    type Target = Arc<Network>;

    fn deref(&self) -> &Self::Target {
        &self.network
    }
}

impl AsRef<Arc<Network>> for DhttpNetwork {
    fn as_ref(&self) -> &Arc<Network> {
        &self.network
    }
}

impl From<Arc<Network>> for DhttpNetwork {
    fn from(network: Arc<Network>) -> Self {
        Self {
            network,
            deferred_stun_resolver: None,
            _stun_resolver: None,
        }
    }
}

impl DhttpNetwork {
    pub fn new(
        stun_server: Option<Arc<str>>,
        stun_resolver: Option<ArcResolver>,
        devices: &'static Devices,
    ) -> Self {
        let builder = Self::builder().stun_server(stun_server).devices(devices);
        match stun_resolver {
            Some(stun_resolver) => builder.stun_resolver(stun_resolver).build(),
            None => builder.build(),
        }
    }
}

#[bon::bon]
impl DhttpNetwork {
    #[builder(
        start_fn(name = builder, vis = "pub"),
        builder_type(vis = "pub"),
        finish_fn = build
    )]
    fn with_options(
        // Bon reserves `Option<T>` to mean "setter omitted". The outer option
        // carries that builder state; the inner option is the actual STUN
        // server setting, where `None` disables STUN.
        stun_server: Option<Option<Arc<str>>>,
        #[builder(setters(vis = "pub(crate)"))] dns_schemes: Option<Vec<DnsScheme>>,
        resolver: Option<ArcResolver>,
        stun_resolver: Option<ArcResolver>,
        #[builder(default = Devices::global())] devices: &'static Devices,
        #[builder(default = Arc::new(InterfaceManager::new()))] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = Arc::new(DEFAULT_IO_FACTORY))] io_factory: Arc<dyn ProductIO + 'static>,
        #[builder(default = Arc::new(QuicRouter::new()))] quic_router: Arc<QuicRouter>,
        #[builder(default = Arc::new(Locations::new()))] locations: Arc<Locations>,
    ) -> Self {
        let stun_server =
            stun_server.unwrap_or_else(|| Some(Arc::<str>::from(crate::endpoint::STUN_SERVER)));
        let plan = dns_schemes
            .or_else(|| resolver.as_ref().map(|_| Vec::new()))
            .map(|schemes| ResolverPlan::new(schemes, resolver));
        let (stun_resolver, deferred_stun_resolver, keepalive_resolver) =
            match (stun_resolver, plan) {
                (Some(stun_resolver), _) => (stun_resolver.clone(), None, Some(stun_resolver)),
                (None, Some(plan)) if plan.schemes.is_empty() => {
                    let stun_resolver = plan.final_resolver(Resolvers::new());
                    (stun_resolver.clone(), None, Some(stun_resolver))
                }
                (None, Some(_plan)) => {
                    let deferred = Arc::new(DeferredStunResolver::new());
                    let stun_resolver: ArcResolver = deferred.clone();
                    (stun_resolver, Some(deferred), None)
                }
                (None, None) => {
                    let stun_resolver: ArcResolver = Arc::new(SystemResolver);
                    (stun_resolver.clone(), None, Some(stun_resolver))
                }
            };

        let network = Network::builder()
            .maybe_stun_server(stun_server)
            .stun_resolver(stun_resolver)
            .devices(devices)
            .iface_manager(iface_manager)
            .io_factory(io_factory)
            .quic_router(quic_router)
            .locations(locations)
            .build();
        DhttpNetwork {
            network,
            deferred_stun_resolver,
            _stun_resolver: keepalive_resolver,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddns::publishers::PublishScope;
    use crate::dquic::resolver::{Publish, PublishFuture};
    use futures::FutureExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }

    impl std::fmt::Display for CountingResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("counting resolver")
        }
    }

    impl Resolve for CountingResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
            use futures::{FutureExt, StreamExt, stream};

            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    #[derive(Debug)]
    struct CountingPublisher {
        calls: Arc<AtomicUsize>,
    }

    impl std::fmt::Display for CountingPublisher {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("counting publisher")
        }
    }

    impl Publish for CountingPublisher {
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(()) }.boxed()
        }
    }

    #[derive(Debug)]
    struct NamedResolver(&'static str);

    impl std::fmt::Display for NamedResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Resolve for NamedResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
            use futures::{StreamExt, stream};

            async move { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    fn resolver_names(resolver: &ArcResolver) -> Vec<String> {
        let any: &dyn std::any::Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("resolver should be a resolver chain");
        resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect()
    }

    fn arc_resolvers_names(resolvers: &ArcResolvers) -> Vec<String> {
        resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect()
    }

    fn publisher_names(publishers: &Publishers) -> Vec<String> {
        publishers
            .iter()
            .map(|publisher| publisher.to_string())
            .collect()
    }

    #[tokio::test]
    async fn endpoint_dns_plan_defaults_when_no_ops() {
        let network = Network::builder().build();
        let plan = EndpointDnsPlan::new();
        let built = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect("default plan should build");

        let names = resolver_names(&built.endpoint_resolver);
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("DeferredResolver("))
        );
        assert!(names.iter().any(|name| name == "mDNS resolvers"));
        assert!(names.iter().any(|name| name == "System DNS Resolver"));

        let publisher_names = publisher_names(&built.endpoint_publishers);
        assert!(
            publisher_names
                .iter()
                .any(|name| name.starts_with("DeferredResolver("))
        );
        assert!(publisher_names.iter().any(|name| name == "mDNS resolvers"));
    }

    #[tokio::test]
    async fn endpoint_dns_plan_custom_resolver_only_has_no_publishers() {
        let network = Network::builder().build();
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = EndpointDnsPlan::new().with_resolver(custom);
        let built = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect("custom resolver plan should build");

        assert_eq!(
            resolver_names(&built.endpoint_resolver),
            vec!["counting resolver"]
        );
        assert!(built.endpoint_publishers.iter().next().is_none());
    }

    #[tokio::test]
    async fn endpoint_dns_plan_custom_publisher_only_is_empty_resolver_error() {
        let network = Network::builder().build();
        let publisher = Arc::new(CountingPublisher {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = EndpointDnsPlan::new().with_publisher(PublishScope::WideArea, publisher);
        let error = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect_err("publisher-only plan should not build a resolver");

        assert!(matches!(error, BuildEndpointDnsError::EmptyResolver));
    }

    #[tokio::test]
    async fn endpoint_dns_plan_deduplicates_dns_schemes_but_not_custom_resolvers() {
        let network = Network::builder().build();
        let calls = Arc::new(AtomicUsize::new(0));
        let first: ArcResolver = Arc::new(CountingResolver {
            calls: calls.clone(),
        });
        let second = first.clone();
        let plan = EndpointDnsPlan::new()
            .with_dns(DnsScheme::System)
            .with_resolver(first)
            .with_dns(DnsScheme::System)
            .with_resolver(second);
        let built = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect("mixed plan should build");

        assert_eq!(
            resolver_names(&built.endpoint_resolver),
            vec![
                "System DNS Resolver".to_string(),
                "counting resolver".to_string(),
                "counting resolver".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn endpoint_dns_plan_h3_underlay_uses_custom_without_system_fallback() {
        let network = Network::builder().build();
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = EndpointDnsPlan::new()
            .with_dns(DnsScheme::H3)
            .with_resolver(custom);
        let built = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect("h3 plus custom resolver should build");

        assert_eq!(
            resolver_names(&built.endpoint_h3_underlay),
            vec!["counting resolver"]
        );
    }

    #[tokio::test]
    async fn endpoint_dns_plan_h3_underlay_adds_system_without_custom_or_system() {
        let network = Network::builder().build();
        let plan = EndpointDnsPlan::new().with_dns(DnsScheme::H3);
        let built = plan
            .build_endpoint_dns(network, Arc::new(Vec::new()))
            .await
            .expect("h3-only plan should build");

        assert_eq!(
            resolver_names(&built.endpoint_h3_underlay),
            vec!["System DNS Resolver"]
        );
    }

    #[tokio::test]
    async fn build_stun_dns_keeps_h3_position_and_custom_resolvers() {
        let network = Network::builder().build();
        let h3_marker: ArcResolver = Arc::new(NamedResolver("stun h3 marker"));
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = EndpointDnsPlan::new()
            .with_dns(DnsScheme::H3)
            .with_resolver(custom)
            .with_dns(DnsScheme::System);
        let stun_dns = plan
            .build_stun_dns(Some(h3_marker), network, Arc::new(Vec::new()))
            .await
            .expect("stun dns should build");

        assert_eq!(
            arc_resolvers_names(&stun_dns),
            vec![
                "stun h3 marker".to_string(),
                "counting resolver".to_string(),
                "System DNS Resolver".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn from_arc_network_preserves_external_network() {
        let network = Network::builder().build();
        let dhttp_network = DhttpNetwork::from(network.clone());

        assert!(Arc::ptr_eq(dhttp_network.as_ref(), &network));
        assert!(Arc::ptr_eq(dhttp_network.deref(), &network));
    }

    #[tokio::test]
    async fn builder_defaults_stun_server_to_dhttp_constant() {
        let dhttp_network = DhttpNetwork::builder().build();

        assert_eq!(
            dhttp_network.network().quic().stun_server().as_deref(),
            Some(crate::endpoint::STUN_SERVER)
        );
    }

    #[tokio::test]
    async fn builder_allows_disabling_stun_server() {
        let dhttp_network = DhttpNetwork::builder().stun_server(None).build();

        assert_eq!(dhttp_network.network().quic().stun_server(), None);
    }

    #[tokio::test]
    async fn builder_allows_custom_stun_server() {
        let dhttp_network = DhttpNetwork::builder()
            .stun_server(Some(Arc::from("custom.stun.example:3478")))
            .build();

        assert_eq!(
            dhttp_network.network().quic().stun_server().as_deref(),
            Some("custom.stun.example:3478")
        );
    }

    #[tokio::test]
    async fn builder_forwards_core_network_options() {
        let iface_manager = Arc::new(crate::dquic::net::InterfaceManager::new());
        let io_factory: Arc<dyn crate::dquic::net::ProductIO + 'static> =
            Arc::new(crate::dquic::network::NullIoFactory);
        let stun_resolver: Arc<dyn Resolve + Send + Sync> =
            Arc::new(crate::dquic::resolver::handy::SystemResolver);
        let quic_router = Arc::new(crate::dquic::net::QuicRouter::new());
        let locations = Arc::new(crate::dquic::net::Locations::new());

        let dhttp_network = DhttpNetwork::builder()
            .iface_manager(iface_manager.clone())
            .io_factory(io_factory.clone())
            .stun_resolver(stun_resolver.clone())
            .stun_server(Some(Arc::from("builder.stun.example:3478")))
            .quic_router(quic_router.clone())
            .locations(locations.clone())
            .build();
        let quic = dhttp_network.network().quic();

        assert!(Arc::ptr_eq(&quic.iface_manager(), &iface_manager));
        assert!(Arc::ptr_eq(&quic.io_factory(), &io_factory));
        assert!(Arc::ptr_eq(&quic.stun_resolver(), &stun_resolver));
        assert_eq!(
            quic.stun_server().as_deref(),
            Some("builder.stun.example:3478")
        );
        assert!(Arc::ptr_eq(&quic.quic_router(), &quic_router));
        assert!(Arc::ptr_eq(&quic.locations(), &locations));
    }

    #[tokio::test]
    async fn builder_derives_stun_resolver_from_custom_resolver() {
        use futures::StreamExt;

        let calls = Arc::new(AtomicUsize::new(0));
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver {
            calls: calls.clone(),
        });

        let dhttp_network = DhttpNetwork::builder().resolver(resolver).build();
        let mut records = dhttp_network
            .network()
            .quic()
            .stun_resolver()
            .lookup("stun.example.test:3478")
            .await
            .expect("custom resolver should resolve STUN server");

        assert!(records.next().await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn h3_only_network_stun_resolver_starts_deferred_without_system_final_resolver() {
        let dhttp_network = DhttpNetwork::builder()
            .dns_schemes(vec![DnsScheme::H3])
            .build();

        let stun_resolver = dhttp_network.network().quic().stun_resolver();
        let any: &dyn std::any::Any = stun_resolver.as_ref();

        assert!(any.downcast_ref::<DeferredStunResolver>().is_some());
    }

    #[tokio::test]
    async fn explicit_custom_network_stun_resolver_is_not_augmented_with_system() {
        let calls = Arc::new(AtomicUsize::new(0));
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: calls.clone(),
        });

        let dhttp_network = DhttpNetwork::builder().resolver(custom).build();
        let resolver = dhttp_network.network().quic().stun_resolver();

        assert_eq!(resolver.to_string(), "counting resolver");
    }

}
