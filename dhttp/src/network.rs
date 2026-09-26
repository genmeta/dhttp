use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use qbase::net::addr::EndpointAddr;
use qconn::{BelongsTo, Scope, Scopes};
use qprotocol::{Dock, QuicProtocol, UdpSocket};

use crate::{Error, Result, ShutdownReport, endpoint::Endpoint, transport::QuicTransport};

#[derive(Clone)]
pub struct NetworkConfig {
    pub listen: Vec<ListenConfig>,
}

#[derive(Clone)]
pub enum ListenConfig {
    Scope(Scopes),
    Interface { device: String, scopes: Scopes },
}

/// Process-wide transport resources. Socket ownership and receive tasks live in Dock.
pub struct DhttpNetwork {
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
    addresses: qprotocol::AddressBook,
}

/// A connection belongs to the same identity pair regardless of which peer dialed.
/// TODO: Dispatch accepted bidirectional streams on outbound connections too.
type ConnectionKey = (Arc<str>, Arc<str>);

static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();

impl DhttpNetwork {
    pub(crate) async fn accept_connections(
        &self,
        name: Arc<str>,
        scopes: Scopes,
    ) -> Result<(
        tokio::sync::mpsc::UnboundedReceiver<Result<h3x::H3Connection<QuicTransport>>>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        let endpoint = Endpoint::quic_endpoint(&name).await?;
        if qconn::ServerRegistry::global().get(&name).is_some() {
            // TODO: Distinguish a clone of this Endpoint (AlreadyListening) from
            // a separately loaded Endpoint (NameInUse) without an owner registry.
            return Err(Error::NameInUse {
                name: name.to_string(),
            });
        }
        let (accepted_tx, accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let pool = self.pool.clone();
        let local_name = name.clone();
        endpoint
            .listen(scopes, move |accepted| {
                let result = accepted
                    .map_err(|source| Error::Quic {
                        source: Arc::new(source),
                    })
                    .and_then(|(remote, local, connection)| {
                        let connection = Arc::new(connection);
                        let transport = QuicTransport {
                            handshake: Arc::new(qtls::HandshakeSummary {
                                alpn: Some(bytes::Bytes::copy_from_slice(connection.alpn())),
                                local: Some(local),
                                remote,
                            }),
                            connection: connection.clone(),
                            role: h3x::Role::Server,
                        };
                        let h3 = h3x::H3Connection::new(transport, h3x::Settings::default())
                            .map_err(|source| Error::Http3 {
                                source: Arc::new(source),
                            })?;
                        if let Some(remote_name) = h3.transport().handshake.remote.as_ref() {
                            // The first accepted connection owns the inbound slot.
                            // get() can open new streams on that connection too.
                            // Later accepted connections are served outside the pool.
                            let _ = pool.insert(
                                (local_name.clone(), Arc::from(remote_name.name())),
                                h3.clone(),
                            );
                        }
                        // TODO: An unauthenticated peer has no reusable identity key.
                        Ok(h3)
                    });
                if let Err(undelivered) = accepted_tx.send(result)
                    && let Ok(h3) = undelivered.0
                {
                    if let Some(remote) = h3.transport().handshake.remote.as_ref() {
                        pool.remove_connection(
                            &(local_name.clone(), Arc::from(remote.name())),
                            &h3,
                        );
                    }
                    let _ = h3.close("listener stopped", 0);
                }
            })
            .map_err(|source| Error::Quic {
                source: Arc::new(source),
            })?;
        let owner = qconn::ServerRegistry::global()
            .get(&name)
            .expect("listen registered server");
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = cancel_rx.await;
            if qconn::ServerRegistry::global()
                .get(&name)
                .is_some_and(|current| Arc::ptr_eq(&current, &owner))
            {
                qconn::ServerRegistry::global().remove(&name);
            }
        });
        Ok((accepted_rx, cancel_tx))
    }

    pub async fn init(config: NetworkConfig) -> Result<&'static Self> {
        if NETWORK.get().is_some() {
            return Err(Error::AlreadyInitialized);
        }
        let ran = AtomicBool::new(false);
        let network = NETWORK
            .get_or_try_init(|| async {
                ran.store(true, Ordering::Relaxed);
                let devices = netdev::get_interfaces();
                validate_config(&config, &devices)?;
                crate::trust::initialize()?;
                let network = Self {
                    pool: h3x::Pool::new(Endpoint::open_outbound),
                    addresses: qprotocol::AddressBook::new(),
                };
                let admission = network.bind_snapshot(&config, &devices);
                let router = qtransport::router::QuicRouter::global().clone();
                QuicProtocol::global().on_receive(move |bytes, pathway, link| {
                    if admission
                        .get(&link.dst)
                        .is_some_and(|scopes| link.src.belongs_to(*scopes))
                    {
                        router.receive(bytes, pathway, link, 8);
                    }
                });
                // TODO: Persist selection rules and observe interface changes. The two
                // retained fields cannot own a cancellable watcher or binding map.
                Ok::<DhttpNetwork, Error>(network)
            })
            .await?;
        if ran.load(Ordering::Relaxed) {
            Ok(network)
        } else {
            Err(Error::AlreadyInitialized)
        }
    }

    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
    }

    pub async fn shutdown(&self, _deadline: Instant) -> Result<ShutdownReport> {
        for h3 in self.pool.drain() {
            let _ = h3.close("network shutdown", 0);
        }
        Dock::global().shutdown();
        QuicProtocol::global().on_receive(|_, _, _| {});
        // TODO: Withdraw all registry entries, cancel active exchanges, clear
        // published addresses, and reject new listeners after shutdown. Neither
        // listener owners nor their tasks are retained by this network.
        Ok(ShutdownReport::default())
    }

    pub(crate) fn forget_connection(
        &self,
        local_name: &Arc<str>,
        h3: &h3x::H3Connection<QuicTransport>,
    ) {
        if let Some(remote) = h3.transport().handshake.remote.as_ref() {
            self.pool
                .remove_connection(&(local_name.clone(), Arc::from(remote.name())), h3);
        }
    }

    fn bind_snapshot(
        &self,
        config: &NetworkConfig,
        devices: &[netdev::Interface],
    ) -> HashMap<SocketAddr, Scopes> {
        let mut admission = HashMap::new();
        let mut selected = HashMap::<String, Scopes>::new();
        for rule in &config.listen {
            for device in devices.iter().filter(|device| device.is_up()) {
                let scopes = match rule {
                    ListenConfig::Scope(scopes) => *scopes,
                    ListenConfig::Interface {
                        device: name,
                        scopes,
                    } if *name == device.name => *scopes,
                    _ => continue,
                };
                let scopes = if device.is_loopback() {
                    scopes
                        .contains(Scope::Loopback)
                        .then_some(Scopes::from(Scope::Loopback))
                } else {
                    match (
                        scopes.contains(Scope::Internal),
                        scopes.contains(Scope::External),
                    ) {
                        (true, true) => Some(Scope::Internal | Scope::External),
                        (true, false) => Some(Scope::Internal.into()),
                        (false, true) => Some(Scope::External.into()),
                        _ => None,
                    }
                };
                if let Some(scopes) = scopes {
                    selected
                        .entry(device.name.clone())
                        .and_modify(|current| *current = *current | scopes)
                        .or_insert(scopes);
                }
            }
        }
        for device in devices {
            let Some(scopes) = selected.get(&device.name).copied() else {
                continue;
            };
            for address in device
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .chain(device.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
            {
                if address.is_unspecified() || address.is_multicast() {
                    continue;
                }
                let external = scopes.contains(Scope::External)
                    && !matches!(address, IpAddr::V4(ip) if ip.is_link_local())
                    && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local());
                let effective = match (
                    scopes.contains(Scope::Loopback),
                    scopes.contains(Scope::Internal),
                    external,
                ) {
                    (true, _, _) => Scope::Loopback.into(),
                    (_, true, true) => Scope::Internal | Scope::External,
                    (_, true, false) => Scope::Internal.into(),
                    (_, false, true) => Scope::External.into(),
                    _ => continue,
                };
                let bound = match address {
                    IpAddr::V4(ip) => SocketAddr::new(ip.into(), 0),
                    IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                        ip,
                        0,
                        0,
                        if ip.is_unicast_link_local() {
                            device.index
                        } else {
                            0
                        },
                    )),
                };
                let Ok(bound_device) = qudp::BoundDevice::new(&device.name, device.index) else {
                    continue;
                };
                let Ok(socket) = UdpSocket::bind_to_device(bound, bound_device).map(Arc::new)
                else {
                    continue;
                };
                let Ok(actual) = socket.local_addr() else {
                    continue;
                };
                if !Dock::global().add(socket.clone()).unwrap_or(false) {
                    continue;
                }
                let endpoint = EndpointAddr::direct(actual);
                if QuicProtocol::global().register(endpoint, &socket).is_err() {
                    Dock::global().remove_bound(actual);
                    continue;
                }
                if effective.contains(Scope::Internal) || effective.contains(Scope::Loopback) {
                    let _ = self.addresses.insert_inner(actual, endpoint);
                }
                admission.insert(actual, effective);
            }
        }
        admission
    }
}

fn validate_config(config: &NetworkConfig, devices: &[netdev::Interface]) -> Result<()> {
    if config.listen.is_empty() {
        return Err(Error::InvalidNetworkConfig {
            message: "listen rules are empty".into(),
        });
    }
    for rule in &config.listen {
        let (scopes, device) = match rule {
            ListenConfig::Scope(scopes) => (*scopes, None),
            ListenConfig::Interface { device, scopes } => (*scopes, Some(device)),
        };
        if ![Scope::Loopback, Scope::Internal, Scope::External]
            .into_iter()
            .any(|scope| scopes.contains(scope))
        {
            return Err(Error::InvalidNetworkConfig {
                message: "a listen rule has no scopes".into(),
            });
        }
        if let Some(name) = device {
            let Some(found) = devices.iter().find(|candidate| candidate.name == *name) else {
                return Err(Error::InvalidNetworkConfig {
                    message: format!("interface {name} does not exist"),
                });
            };
            if (found.is_loopback()
                && (scopes.contains(Scope::Internal) || scopes.contains(Scope::External)))
                || (!found.is_loopback() && scopes.contains(Scope::Loopback))
            {
                return Err(Error::InvalidNetworkConfig {
                    message: format!("interface {name} is incompatible with its scopes"),
                });
            }
        }
    }
    Ok(())
}
