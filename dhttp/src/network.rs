use std::{ops::Deref, sync::Arc};

use crate::ddns::{
    ArcPublisher, ArcResolver, BuildDhttpNetworkWithDnsError, DhttpDnsPlan,
    dhttp_network_builder_with_dns,
    publishers::PublishScope,
    resolvers::{DnsScheme, Resolvers, deferred::DeferredResolver, weak::WeakResolver},
};
use crate::dquic::{
    Network,
    binds::BindPattern,
    net::{
        Devices, InterfaceManager, LocalEndpoints, ProductIO, QuicRouter, handy::DEFAULT_IO_FACTORY,
    },
};

pub(crate) type ArcResolvers = Arc<Resolvers>;
pub(crate) type DeferredStunResolver = DeferredResolver<WeakResolver<Resolvers>>;

#[derive(Clone)]
pub struct DhttpNetwork {
    network: Arc<Network>,
    _deferred_stun_resolver: Option<Arc<DeferredStunResolver>>,
    _stun_resolver: Option<ArcResolver>,
}

impl DhttpNetwork {
    #[must_use]
    pub fn network(&self) -> &Arc<Network> {
        &self.network
    }

    pub(crate) fn from_deferred_stun_resolver(
        network: Arc<Network>,
        deferred_stun_resolver: Arc<DeferredStunResolver>,
        stun_resolver: ArcResolvers,
    ) -> Result<Self, crate::ddns::resolvers::deferred::SetDeferredResolverError> {
        deferred_stun_resolver.set(WeakResolver::new(Arc::downgrade(&stun_resolver)))?;
        let keepalive: ArcResolver = stun_resolver;
        Ok(Self {
            network,
            _deferred_stun_resolver: Some(deferred_stun_resolver),
            _stun_resolver: Some(keepalive),
        })
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
            _deferred_stun_resolver: None,
            _stun_resolver: None,
        }
    }
}

impl DhttpNetwork {
    pub async fn new(
        stun_server: Option<Arc<str>>,
        stun_resolver: Option<ArcResolver>,
        devices: &'static Devices,
    ) -> Result<Self, BuildDhttpNetworkWithDnsError> {
        let builder = Self::builder().stun_server(stun_server).devices(devices);
        match stun_resolver {
            Some(stun_resolver) => builder.stun_resolver(stun_resolver).build().await,
            None => builder.build().await,
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
    async fn with_options(
        #[builder(field)] dns_plan: DhttpDnsPlan,
        // Bon reserves `Option<T>` to mean "setter omitted". The outer option
        // carries that builder state; the inner option is the actual STUN
        // server setting, where `None` disables STUN.
        stun_server: Option<Option<Arc<str>>>,
        stun_resolver: Option<ArcResolver>,
        #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
        #[builder(default = Arc::<str>::from(crate::ddns::resolvers::DHTTP_H3_DNS_SERVER))]
        h3_dns_server: Arc<str>,
        #[builder(default = Devices::global())] devices: &'static Devices,
        #[builder(default = Arc::new(InterfaceManager::new()))] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = Arc::new(DEFAULT_IO_FACTORY))] io_factory: Arc<dyn ProductIO + 'static>,
        #[builder(default = Arc::new(QuicRouter::new()))] quic_router: Arc<QuicRouter>,
        #[builder(default = Arc::new(LocalEndpoints::new()))] local_endpoints: Arc<LocalEndpoints>,
    ) -> Result<Self, BuildDhttpNetworkWithDnsError> {
        let stun_server =
            stun_server.unwrap_or_else(|| Some(Arc::<str>::from(crate::endpoint::STUN_SERVER)));

        if let Some(stun_resolver) = stun_resolver {
            let network = Network::builder()
                .maybe_stun_server(stun_server)
                .stun_resolver(stun_resolver.clone())
                .devices(devices)
                .iface_manager(iface_manager)
                .io_factory(io_factory)
                .quic_router(quic_router)
                .local_endpoints(local_endpoints)
                .build();
            return Ok(Self {
                network,
                _deferred_stun_resolver: None,
                _stun_resolver: Some(stun_resolver),
            });
        }

        dhttp_network_builder_with_dns(
            |stun_resolver| {
                Network::builder()
                    .maybe_stun_server(stun_server)
                    .stun_resolver(stun_resolver)
                    .devices(devices)
                    .iface_manager(iface_manager)
                    .io_factory(io_factory)
                    .quic_router(quic_router)
                    .local_endpoints(local_endpoints)
                    .build()
            },
            &dns_plan,
        )
        .bind(bind)
        .h3_dns_server(h3_dns_server)
        .build()
        .await
    }
}

impl<S: dhttp_network_with_options_builder::State> DhttpNetworkWithOptionsBuilder<S> {
    /// Replace the DNS plan used to construct the STUN resolver.
    pub fn dns_plan(mut self, dns_plan: DhttpDnsPlan) -> Self {
        self.dns_plan = dns_plan;
        self
    }

    /// Add a built-in DNS scheme to the STUN DNS plan.
    pub fn dns(mut self, scheme: DnsScheme) -> Self {
        self.dns_plan.push_dns(scheme);
        self
    }

    /// Add a custom resolver to the STUN DNS plan.
    pub fn resolver(mut self, resolver: ArcResolver) -> Self {
        self.dns_plan.push_resolver(resolver);
        self
    }

    /// Add a custom publisher operation to the DNS plan.
    ///
    /// Network construction ignores publisher operations while still treating
    /// the DNS plan as explicit, matching endpoint DNS plan semantics.
    pub fn publisher(mut self, scope: PublishScope, publisher: ArcPublisher) -> Self {
        self.dns_plan.push_publisher(scope, publisher);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dquic::resolver::Resolve;
    use futures::FutureExt;
    use std::{
        fmt,
        sync::atomic::{AtomicUsize, Ordering},
    };

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
            use futures::{StreamExt, stream};

            self.calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(stream::empty().boxed()) }.boxed()
        }
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
        let dhttp_network = DhttpNetwork::builder()
            .build()
            .await
            .expect("default network should build");

        assert_eq!(
            dhttp_network.network().quic().stun_server().as_deref(),
            Some(crate::endpoint::STUN_SERVER)
        );
    }

    #[tokio::test]
    async fn builder_allows_disabling_stun_server() {
        let dhttp_network = DhttpNetwork::builder()
            .stun_server(None)
            .build()
            .await
            .expect("network should build with disabled stun server");

        assert_eq!(dhttp_network.network().quic().stun_server(), None);
    }

    #[tokio::test]
    async fn builder_allows_custom_stun_server() {
        let dhttp_network = DhttpNetwork::builder()
            .stun_server(Some(Arc::from("custom.stun.example")))
            .build()
            .await
            .expect("network should build with custom stun server");

        assert_eq!(
            dhttp_network.network().quic().stun_server().as_deref(),
            Some("custom.stun.example")
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
        let local_endpoints = Arc::new(crate::dquic::net::LocalEndpoints::new());

        let dhttp_network = DhttpNetwork::builder()
            .iface_manager(iface_manager.clone())
            .io_factory(io_factory.clone())
            .stun_resolver(stun_resolver.clone())
            .stun_server(Some(Arc::from("builder.stun.example")))
            .quic_router(quic_router.clone())
            .local_endpoints(local_endpoints.clone())
            .build()
            .await
            .expect("network should build with forwarded options");
        let quic = dhttp_network.network().quic();

        assert!(Arc::ptr_eq(&quic.iface_manager(), &iface_manager));
        assert!(Arc::ptr_eq(&quic.io_factory(), &io_factory));
        assert!(Arc::ptr_eq(&quic.stun_resolver(), &stun_resolver));
        assert_eq!(quic.stun_server().as_deref(), Some("builder.stun.example"));
        assert!(Arc::ptr_eq(&quic.quic_router(), &quic_router));
        assert!(Arc::ptr_eq(&quic.local_endpoints(), &local_endpoints));
    }

    #[tokio::test]
    async fn builder_derives_stun_resolver_from_custom_resolver_without_literal_port() {
        use futures::StreamExt;

        let calls = Arc::new(AtomicUsize::new(0));
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(CountingResolver {
            calls: calls.clone(),
        });

        let dhttp_network = DhttpNetwork::builder()
            .resolver(resolver)
            .build()
            .await
            .expect("network should build with custom dns resolver");
        let mut records = dhttp_network
            .network()
            .quic()
            .stun_resolver()
            .lookup("stun.example.test")
            .await
            .expect("custom resolver should resolve STUN server");

        assert!(records.next().await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn h3_only_network_stun_resolver_uses_h3_without_system_final_resolver() {
        let dhttp_network = DhttpNetwork::builder()
            .dns(DnsScheme::H3)
            .build()
            .await
            .expect("h3-only network should build");

        let stun_resolver = dhttp_network.network().quic().stun_resolver();
        let any: &dyn std::any::Any = stun_resolver.as_ref();
        let deferred = any
            .downcast_ref::<DeferredStunResolver>()
            .expect("h3-only network stun resolver is deferred");
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
    async fn explicit_custom_network_stun_resolver_is_not_augmented_with_system() {
        let calls = Arc::new(AtomicUsize::new(0));
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: calls.clone(),
        });

        let dhttp_network = DhttpNetwork::builder()
            .stun_resolver(custom)
            .build()
            .await
            .expect("network should build with explicit stun resolver");
        let resolver = dhttp_network.network().quic().stun_resolver();

        assert_eq!(resolver.to_string(), "counting resolver");
    }
}
