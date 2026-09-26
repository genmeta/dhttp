impl DhttpNetwork {
    pub async fn init(config: NetworkConfig) -> Result<&'static Self> {
        if NETWORK.get().is_some() {
            return Err(Error::AlreadyInitialized);
        }
        // A local flag records whether this invocation performed initialization;
        // no process-level counter or second initialization flag is retained.
        let initialized = std::sync::atomic::AtomicBool::new(false);
        let network = NETWORK
            .get_or_try_init(|| async {
                validate_config(&config, &netdev::get_interfaces())?;
                crate::trust::initialize()?;
                let network = Self {
                    config,
                    endpoints: Mutex::new(HashMap::new()),
                    listeners: Mutex::new(HashMap::new()),
                    pool: h3x::Pool::new(open_outbound),
                    bindings: Mutex::new(HashMap::new()),
                    addresses: qprotocol::AddressBook::new(),
                    stop: CancellationToken::new(),
                };
                update_bindings(&network);
                initialized.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok::<_, Error>(network)
            })
            .await?;
        if !initialized.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::AlreadyInitialized);
        }
        let router = qtransport::router::QuicRouter::global().clone();
        QuicProtocol::global().on_receive(move |bytes, pathway, link| {
            let admitted = !network.stop.is_cancelled()
                && network.bindings.lock().unwrap().values().any(|binding| {
                    binding.socket.local_addr().ok() == Some(link.dst)
                        && link.src.belongs_to(binding.scopes)
                });
            if admitted {
                router.receive(bytes, pathway, link, 8);
            }
        });
        tokio::spawn(async move {
            // Interface snapshots reapply the original rules and own no parallel
            // state. Cancellation cleanup uses the same binding withdrawal path.
            let mut updates = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = network.stop.cancelled() => break,
                    _ = updates.tick() => update_bindings(network),
                }
            }
            clear_bindings(network);
        });
        Ok(network)
    }
    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
    }
    pub fn shutdown(&self) -> Result<()> {
        self.stop.cancel();
        let names = self
            .endpoints
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut result = Ok(());
        for name in names {
            if let Err(error) = close_endpoint(self, &name) {
                result = Err(error);
            }
        }
        for connection in self.pool.drain() {
            if let Err(error) = connection.close("network shutdown", 0) {
                result = Err(h3_error(error));
            }
        }
        clear_bindings(self);
        QuicProtocol::global().on_receive(|_, _, _| {});
        result
    }
}

fn endpoint_connections(network: &DhttpNetwork, name: &Arc<str>) -> Arc<EndpointConnections> {
    network
        .endpoints
        .lock()
        .unwrap()
        .entry(name.clone())
        .or_insert_with(|| {
            Arc::new(EndpointConnections {
                stop: network.stop.child_token(),
                connections: Mutex::new(Vec::new()),
            })
        })
        .clone()
}
fn check_open(network: &DhttpNetwork, owner: &EndpointConnections) -> Result<()> {
    if network.stop.is_cancelled() {
        Err(Error::NetworkClosed)
    } else if owner.stop.is_cancelled() {
        Err(Error::EndpointClosed)
    } else {
        Ok(())
    }
}
fn close_endpoint(network: &DhttpNetwork, name: &Arc<str>) -> Result<()> {
    let owner = endpoint_connections(network, name);
    let connections = {
        let mut connections = owner.connections.lock().unwrap();
        owner.stop.cancel();
        let connections = std::mem::take(&mut *connections);
        if let Some(registration) = network.listeners.lock().unwrap().remove(name) {
            registration.stop.cancel();
            withdraw_listener(name, &registration);
        }
        connections
    };
    let mut result = Ok(());
    for connection in connections {
        forget_pool_connection(network, name, &connection);
        if let Err(error) = connection.close("endpoint closed", 0) {
            result = Err(h3_error(error));
        }
    }
    result
}
fn withdraw_listener(name: &str, registration: &ListenerRegistration) {
    let registry = qconn::ServerRegistry::global();
    if registry
        .get(name)
        .is_some_and(|current| Arc::ptr_eq(&current, &registration.qconn_owner))
    {
        registry.remove(name);
    }
}
