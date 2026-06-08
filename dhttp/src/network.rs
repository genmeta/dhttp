use std::{ops::Deref, sync::Arc};

use crate::ddns::resolvers::{
    DnsScheme, Resolvers, deferred::DeferredResolver, weak::WeakResolver,
};
use crate::dquic::{
    Network,
    binds::BindPattern,
    net::{Devices, InterfaceManager, Locations, ProductIO, QuicRouter, handy::DEFAULT_IO_FACTORY},
    resolver::{Resolve, handy::SystemResolver},
};

pub(crate) type DynResolver = dyn Resolve + Send + Sync;
pub(crate) type ArcResolver = Arc<DynResolver>;
pub(crate) type DeferredStunResolver = DeferredResolver<WeakResolver<Resolvers>>;

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

    pub(crate) fn schemes(&self) -> &[DnsScheme] {
        &self.schemes
    }

    pub(crate) fn custom(&self) -> Option<ArcResolver> {
        self.custom.clone()
    }

    pub(crate) fn uses_h3(&self) -> bool {
        self.schemes.contains(&DnsScheme::H3)
    }

    pub(crate) async fn build_resolvers(
        &self,
        h3_resolver: Option<ArcResolver>,
        network: Arc<Network>,
        bind: Arc<Vec<BindPattern>>,
    ) -> Resolvers {
        let mut builder = Resolvers::builder();

        if self.schemes.contains(&DnsScheme::Mdns) {
            builder = builder.mdns(network.clone(), bind).await;
        }

        if self.schemes.contains(&DnsScheme::System) {
            builder = builder.system();
        }

        if self.schemes.contains(&DnsScheme::Http) {
            builder = builder
                .http()
                .expect("BUG: DHTTP HTTP DNS server is a valid URL");
        }

        if self.uses_h3()
            && let Some(h3_resolver) = h3_resolver
        {
            builder = builder.resolver(h3_resolver);
        }

        if let Some(custom) = self.custom.clone() {
            builder = builder.resolver(custom);
        }

        builder.build()
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

    pub(crate) fn resolver_without_h3(&self, mut resolvers: Resolvers) -> ArcResolver {
        if self.uses_h3() && self.custom.is_none() && !self.schemes.contains(&DnsScheme::System) {
            resolvers.push(Arc::new(SystemResolver));
        }
        self.select_resolver(resolvers)
    }
}

#[derive(Clone)]
pub struct DhttpNetwork {
    network: Arc<Network>,
    deferred_stun_resolver: Option<Arc<DeferredStunResolver>>,
    stun_resolver_plan: Option<ResolverPlan>,
    _stun_resolver: Option<ArcResolver>,
}

impl DhttpNetwork {
    #[must_use]
    pub fn network(&self) -> &Arc<Network> {
        &self.network
    }

    pub(crate) async fn finish_stun_resolver(
        &mut self,
        h3_resolver: Option<ArcResolver>,
        bind: Arc<Vec<BindPattern>>,
    ) {
        let (Some(deferred), Some(plan)) = (
            self.deferred_stun_resolver.clone(),
            self.stun_resolver_plan.clone(),
        ) else {
            return;
        };

        let resolvers = plan
            .build_resolvers(h3_resolver, self.network.clone(), bind)
            .await;
        let stun_resolver = Arc::new(resolvers);
        deferred
            .set(WeakResolver::new(Arc::downgrade(&stun_resolver)))
            .expect("BUG: network STUN resolver is set exactly once");
        self._stun_resolver = Some(stun_resolver);
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
            stun_resolver_plan: None,
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
        let (stun_resolver, deferred_stun_resolver, stun_resolver_plan, keepalive_resolver) =
            match (stun_resolver, plan) {
                (Some(stun_resolver), _) => {
                    (stun_resolver.clone(), None, None, Some(stun_resolver))
                }
                (None, Some(plan)) if plan.schemes.is_empty() => {
                    let stun_resolver = plan.final_resolver(Resolvers::new());
                    (stun_resolver.clone(), None, None, Some(stun_resolver))
                }
                (None, Some(plan)) => {
                    let deferred = Arc::new(DeferredStunResolver::new());
                    let stun_resolver: ArcResolver = deferred.clone();
                    (stun_resolver, Some(deferred), Some(plan), None)
                }
                (None, None) => {
                    let stun_resolver: ArcResolver = Arc::new(SystemResolver);
                    (stun_resolver.clone(), None, None, Some(stun_resolver))
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
            stun_resolver_plan,
            _stun_resolver: keepalive_resolver,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn resolver_without_h3_keeps_non_h3_schemes_and_custom_resolver() {
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = ResolverPlan::new(
            vec![
                DnsScheme::H3,
                DnsScheme::Mdns,
                DnsScheme::Http,
                DnsScheme::System,
            ],
            Some(custom.clone()),
        );

        let resolver = plan.resolver_without_h3(Resolvers::builder().system().build().with(custom));
        let any: &dyn std::any::Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("resolver_without_h3 returns a resolver chain");
        let names = resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect::<Vec<_>>();

        assert!(names.iter().any(|name| name == "System DNS Resolver"));
        assert!(names.iter().any(|name| name == "counting resolver"));
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("H3 DNS Resolver("))
        );
    }

    #[test]
    fn resolver_without_h3_adds_system_when_h3_only_without_custom() {
        let plan = ResolverPlan::new(vec![DnsScheme::H3], None);

        let resolver = plan.resolver_without_h3(Resolvers::new());
        let any: &dyn std::any::Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("h3-only resolver_without_h3 returns a concrete resolver chain");
        let names = resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["System DNS Resolver"]);
    }

    #[test]
    fn resolver_without_h3_adds_system_to_h3_mdns_without_custom() {
        let plan = ResolverPlan::new(vec![DnsScheme::H3, DnsScheme::Mdns], None);
        let mdns_marker: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });

        let resolver = plan.resolver_without_h3(Resolvers::new().with(mdns_marker));
        let any: &dyn std::any::Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("h3+mdns resolver_without_h3 returns a resolver chain");
        let names = resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect::<Vec<_>>();

        assert!(names.iter().any(|name| name == "counting resolver"));
        assert!(names.iter().any(|name| name == "System DNS Resolver"));
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("H3 DNS Resolver("))
        );
    }

    #[test]
    fn resolver_without_h3_does_not_auto_add_system_when_custom_is_present() {
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let mdns_marker: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = ResolverPlan::new(vec![DnsScheme::H3, DnsScheme::Mdns], Some(custom.clone()));

        let resolver = plan.resolver_without_h3(Resolvers::new().with(mdns_marker).with(custom));
        let any: &dyn std::any::Any = resolver.as_ref();
        let resolvers = any
            .downcast_ref::<Resolvers>()
            .expect("h3+mdns+custom resolver_without_h3 returns a resolver chain");
        let names = resolvers
            .iter()
            .map(|resolver| resolver.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec!["counting resolver", "counting resolver"],
            "custom suppresses automatic System insertion; duplicate marker names represent mdns-marker plus custom"
        );
    }

    #[test]
    fn resolver_without_h3_does_not_override_custom_only_plan() {
        let custom: ArcResolver = Arc::new(CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let plan = ResolverPlan::new(Vec::new(), Some(custom));

        let resolver = plan.resolver_without_h3(Resolvers::new());

        assert_eq!(resolver.to_string(), "counting resolver");
    }
}
