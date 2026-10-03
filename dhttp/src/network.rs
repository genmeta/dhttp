//! Process-wide QUIC resources, interface maintenance and HTTP/3 service registry.
use crate::{
    Body, BoxError, Endpoint, Error, Result, endpoint::handle_request, transport::QuicTransport,
};
use qbase::net::addr::EndpointAddr;
use qconn::{Scope, Scopes};
use qprotocol::{AddressBook, Dock, UdpSocket};
use qrecovery::{recv::StopSending, send::CancelStream};
use qudp::BoundDevice;
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) type BoxService =
    tower::util::BoxCloneService<http::Request<Body>, http::Response<Body>, BoxError>;
#[derive(Clone)]
enum ConnectionKey {
    Incoming {
        local: Arc<str>,
        remote: Option<Arc<str>>,
    },
    Outgoing {
        local: Endpoint,
        remote: Arc<str>,
    },
}

impl ConnectionKey {
    fn names(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Incoming { local, remote } => (Some(local), remote.as_deref()),
            Self::Outgoing { local, remote } => (local.name(), Some(remote)),
        }
    }
}

// The same named peers share a pool entry regardless of who initiated the connection.
impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.names() == other.names()
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.names().hash(state);
    }
}

type H3 = h3x::H3Connection<QuicTransport>;
static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const BINDING_CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub struct DhttpNetwork {
    listeners: Mutex<HashMap<Arc<str>, BoxService>>,
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
}

impl DhttpNetwork {
    /// Prepare all available interfaces and watch for subsequent interface changes.
    /// Repeated or concurrent calls return the same process-wide network. Individual
    /// binding failures are logged and retried on interface changes and periodic checks.
    /// The Tokio runtime must remain alive for the lifetime of the network.
    pub async fn init() -> Result<&'static Self> {
        NETWORK
            .get_or_try_init(|| async {
                crate::trust::initialize()?;
                let mut watcher =
                    netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>()
                        .map_err(std::io::Error::other)?;
                qtransport::router::QuicRouter::global();
                let snapshot = watcher.changed().await.interfaces;
                let mut bindings =
                    InterfaceBindings::new(Dock::global().clone(), AddressBook::global().clone());
                bindings.scan(&snapshot);
                tokio::spawn(watch(watcher, snapshot, bindings));
                Ok::<_, Error>(Self {
                    listeners: Mutex::new(HashMap::new()),
                    pool: h3x::Pool::new(connect),
                })
            })
            .await
    }

    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
    }

    pub(crate) async fn get_connection(
        &'static self,
        local: Endpoint,
        remote: Arc<str>,
    ) -> Result<H3> {
        let key = ConnectionKey::Outgoing { local, remote };
        tokio::time::timeout(CONNECT_TIMEOUT, self.pool.get(&key))
            .await
            .map_err(std::io::Error::other)?
    }

    pub(crate) async fn listen(
        &'static self,
        endpoint: &Endpoint,
        scopes: Scopes,
        service: BoxService,
    ) -> Result<()> {
        let quic = endpoint
            .quic
            .as_ref()
            .ok_or_else(|| Error::InvalidRequest {
                message: "listening requires a local identity".into(),
            })?;
        let name: Arc<str> = Arc::from(quic.identity.name());
        {
            let mut listeners = self.listeners.lock().unwrap();
            if listeners.contains_key(&name) {
                return Err(Error::AlreadyListening);
            }
            if qconn::ServerRegistry::global().get(&name).is_some() {
                return Err(Error::NameInUse {
                    name: name.to_string(),
                });
            }
            quic.listen(scopes, {
                let name = name.clone();
                move |result| {
                    let (remote, local, connection) = match result {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::debug!(endpoint = %name, %error, "incoming connection rejected");
                            return;
                        }
                    };
                    let connection = QuicTransport::new(
                        connection, Some(local), remote, h3x::Role::Server,
                    ).and_then(|transport| {
                        H3::new(transport, h3x::Settings::default()).map_err(Error::from)
                    });
                    let h3 = match connection {
                        Ok(h3) => h3,
                        Err(error) => {
                            tracing::debug!(endpoint = %name, %error, "HTTP/3 setup failed");
                            return;
                        }
                    };
                    let key = ConnectionKey::Incoming {
                        local: name.clone(),
                        remote: h3.transport().handshake.remote.as_ref()
                            .map(|remote| Arc::from(remote.name())),
                    };
                    let _ = self.pool.insert(key.clone(), h3.clone());
                    tokio::spawn(serve_connection(self, key, h3));
                }
            })?;
            listeners.insert(name.clone(), service);
        }
        let _cleanup = scopeguard::guard(name.clone(), |name| {
            let mut listeners = self.listeners.lock().unwrap();
            listeners.remove(&name);
            qconn::ServerRegistry::global().remove(&name);
        });
        std::future::pending().await
    }
}

async fn serve_connection(network: &'static DhttpNetwork, key: ConnectionKey, h3: H3) {
    let name: Option<Arc<str>> = key.names().0.map(Arc::from);
    loop {
        let (mut writer, mut reader) = match h3.accept_bi().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(endpoint = ?name.as_deref(), %error, "stopped accepting HTTP/3 streams");
                break;
            }
        };
        let service = name
            .as_ref()
            .and_then(|name| network.listeners.lock().unwrap().get(name).cloned());
        let Some(service) = service else {
            let code = h3x::ErrorCode::RequestRejected.as_u64();
            reader.stop(code);
            writer.cancel(code);
            continue;
        };
        let qpack = h3.qpack().clone();
        let handshake = h3.transport().handshake.clone();
        let endpoint = name.clone();
        let stream_id = writer.stream_id();
        tokio::spawn(async move {
            if let Err(error) = handle_request(service, writer, reader, qpack, handshake).await {
                tracing::debug!(endpoint = ?endpoint.as_deref(), stream_id, %error, "request exchange failed");
            }
        });
    }
    network.pool.remove_connection(&key, &h3);
}

/// A desired binding without a port. Hardware identity detects interface replacement
/// even when the OS reuses a name and index.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InterfaceAddress {
    name: String,
    index: u32,
    hw_addr: String,
    addr: SocketAddr,
}

struct Binding {
    bound: SocketAddr,
    socket: Arc<UdpSocket>,
    receiver: tokio::task::AbortHandle,
}

/// Only bindings created by this maintenance task belong to this table.
struct InterfaceBindings {
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    bindings: HashMap<InterfaceAddress, Binding>,
}

impl InterfaceBindings {
    fn new(dock: Arc<Dock>, addresses: Arc<AddressBook>) -> Self {
        Self {
            dock,
            addresses,
            bindings: HashMap::new(),
        }
    }

    fn register(&self, socket: Arc<UdpSocket>) -> io::Result<Option<Binding>> {
        let bound = socket.local_addr()?;
        let Some(receiver) = self.dock.add(socket.clone())? else {
            return Ok(None);
        };
        // Dock already registered the direct QUIC endpoint. Publication is our policy.
        let endpoint = EndpointAddr::direct(bound);
        let published = match endpoint.scope() {
            Some(Scope::External) => self.addresses.insert_outer(&socket, endpoint),
            Some(Scope::Loopback | Scope::Internal) => {
                self.addresses.insert_inner(&socket, endpoint)
            }
            None => Ok(()),
        };
        if let Err(error) = published {
            // AddressBook insertion is atomic; preserve any pre-existing publication.
            self.dock.remove(&socket);
            return Err(io::Error::other(error));
        }
        Ok(Some(Binding {
            bound,
            socket,
            receiver,
        }))
    }

    fn withdraw(&self, binding: &Binding) {
        // This task is the only publisher; no per-binding probe or publishing tasks
        // are currently spawned. Any future ones must finish before remove_bound.
        self.addresses.remove_bound(binding.bound);
        self.dock.remove(&binding.socket);
    }

    fn scan(&mut self, snapshot: &HashMap<u32, netwatcher::Interface>) {
        let current = interfaces(snapshot);
        let obsolete = self
            .bindings
            .iter()
            .filter_map(|(key, binding)| {
                let live = !binding.receiver.is_finished()
                    && self
                        .dock
                        .find_socket(binding.bound)
                        .is_some_and(|socket| Arc::ptr_eq(&socket, &binding.socket));
                (!live || !current.contains_key(key)).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in obsolete {
            let binding = self.bindings.remove(&key).unwrap();
            self.withdraw(&binding);
        }
        for (key, device) in current {
            if self.bindings.contains_key(&key) {
                continue;
            }
            match UdpSocket::bind_to_device(key.addr, device)
                .and_then(|socket| self.register(Arc::new(socket)))
            {
                Ok(Some(binding)) => {
                    self.bindings.insert(key, binding);
                }
                Ok(None) => tracing::warn!(addr = %key.addr, "socket address already registered"),
                Err(error) => {
                    tracing::warn!(addr = %key.addr, %error, "socket binding or publication failed")
                }
            }
        }
    }
}

impl Drop for InterfaceBindings {
    fn drop(&mut self) {
        for binding in self.bindings.values() {
            self.withdraw(binding);
        }
    }
}

fn interfaces(
    snapshot: &HashMap<u32, netwatcher::Interface>,
) -> HashMap<InterfaceAddress, BoundDevice> {
    let mut current = HashMap::new();
    for interface in snapshot.values() {
        let device = match BoundDevice::new(interface.name.clone(), interface.index) {
            Ok(device) => device,
            Err(error) => {
                tracing::warn!(interface = %interface.name, %error, "interface unavailable");
                continue;
            }
        };
        for record in &interface.ips {
            let ip = record.ip;
            if ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let addr = match ip {
                IpAddr::V4(ip) => SocketAddr::new(ip.into(), 0),
                IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    0,
                    0,
                    if ip.is_unicast_link_local() {
                        interface.index
                    } else {
                        0
                    },
                )),
            };
            current.insert(
                InterfaceAddress {
                    name: interface.name.clone(),
                    index: interface.index,
                    hw_addr: interface.hw_addr.clone(),
                    addr,
                },
                device.clone(),
            );
        }
    }
    current
}

async fn watch(
    mut watcher: netwatcher::AsyncWatch,
    mut snapshot: HashMap<u32, netwatcher::Interface>,
    mut bindings: InterfaceBindings,
) {
    let mut check = tokio::time::interval_at(
        tokio::time::Instant::now() + BINDING_CHECK_INTERVAL,
        BINDING_CHECK_INTERVAL,
    );
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            update = watcher.changed() => snapshot = update.interfaces,
            _ = check.tick() => {}
        }
        bindings.scan(&snapshot);
    }
}

async fn connect(key: ConnectionKey) -> Result<H3> {
    let ConnectionKey::Outgoing { local, remote } = &key else {
        return Err(Error::InvalidRequest {
            message: "cannot initiate a connection with an incoming key".into(),
        });
    };
    let network = DhttpNetwork::global()?;
    let (local, remote, connection) = match &local.quic {
        Some(quic) => quic.connect(remote.to_string()).await?,
        None => crate::endpoint::anonymous::connect(remote.to_string()).await?,
    };
    let transport = QuicTransport::new(connection, local, Some(remote), h3x::Role::Client)?;
    let h3 = H3::new(transport, h3x::Settings::default())?;
    tokio::spawn(serve_connection(network, key, h3.clone()));
    Ok(h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_keys_share_named_peers_across_directions_and_separate_anonymous_peers() {
        let local: Arc<str> = Arc::from("alice.dhttp.net");
        let remote: Arc<str> = Arc::from("bob.dhttp.net");
        let mut entries = HashMap::from([(
            ConnectionKey::Incoming {
                local: local.clone(),
                remote: Some(remote.clone()),
            },
            "named",
        )]);
        assert_eq!(
            entries.get(&ConnectionKey::Outgoing {
                local: crate::endpoint::test_support::named("alice"),
                remote: Arc::from("bob.dhttp.net"),
            }),
            Some(&"named"),
        );
        entries.insert(
            ConnectionKey::Incoming {
                local: local.clone(),
                remote: None,
            },
            "anonymous peer",
        );
        entries.insert(
            ConnectionKey::Outgoing {
                local: Endpoint::new(None),
                remote: local,
            },
            "anonymous local",
        );
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn different_origin_ports_do_not_share_connections() {
        let key = |remote: &str| ConnectionKey::Outgoing {
            local: crate::endpoint::test_support::named("alice"),
            remote: Arc::from(remote),
        };
        let entries = HashMap::from([
            (key("ddns.genmeta.net:4433"), "first"),
            (key("ddns.genmeta.net:8443"), "second"),
        ]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(&key("ddns.genmeta.net:4433")), Some(&"first"));
        assert_eq!(entries.get(&key("ddns.genmeta.net:8443")), Some(&"second"));
    }

    #[test]
    fn interface_snapshot_filters_unusable_ips_and_preserves_ipv6_scope() {
        let snapshot = HashMap::from([
            (
                7,
                netwatcher::Interface {
                    index: 7,
                    name: "test7".into(),
                    hw_addr: String::new(),
                    ips: [
                        "0.0.0.0",
                        "::",
                        "224.0.0.1",
                        "ff02::1",
                        "127.0.0.1",
                        "192.168.1.2",
                        "169.254.1.2",
                        "fe80::1234",
                        "2001:db8::1",
                        "::1",
                    ]
                    .map(|ip| netwatcher::IpRecord {
                        ip: ip.parse().unwrap(),
                        prefix_len: 0,
                    })
                    .into(),
                },
            ),
            (
                0,
                netwatcher::Interface {
                    index: 0,
                    name: "invalid".into(),
                    hw_addr: String::new(),
                    ips: vec![netwatcher::IpRecord {
                        ip: "10.0.0.1".parse().unwrap(),
                        prefix_len: 8,
                    }],
                },
            ),
        ]);
        let current = interfaces(&snapshot);
        let addresses: std::collections::HashSet<_> = current.keys().map(|key| key.addr).collect();
        assert_eq!(
            addresses,
            [
                "127.0.0.1:0",
                "192.168.1.2:0",
                "169.254.1.2:0",
                "[fe80::1234%7]:0",
                "[2001:db8::1]:0",
                "[::1]:0"
            ]
            .map(|addr| addr.parse::<SocketAddr>().unwrap())
            .into()
        );
        assert!(
            current
                .iter()
                .all(|(_, device)| device.name() == "test7" && device.index().get() == 7)
        );
    }

    fn loopback_interface() -> netwatcher::Interface {
        let mut loopback = netwatcher::list_interfaces()
            .unwrap()
            .into_values()
            .find(|interface| {
                interface
                    .ips
                    .iter()
                    .any(|record| record.ip == std::net::Ipv4Addr::LOCALHOST)
            })
            .expect("an IPv4 loopback interface");
        loopback
            .ips
            .retain(|record| record.ip == std::net::Ipv4Addr::LOCALHOST);
        loopback
    }

    fn isolated_bindings() -> InterfaceBindings {
        InterfaceBindings::new(
            Dock::new(Arc::new(qprotocol::topology::Topology::new(
                Arc::new(qprotocol::StunProtocol::new()),
                Arc::new(qprotocol::ForwardProtocol::new()),
                Arc::new(qprotocol::QuicProtocol::new()),
            ))),
            Arc::new(AddressBook::new()),
        )
    }

    #[tokio::test]
    async fn scan_preserves_ports_and_foreign_sockets_and_withdraws_all_aliases() {
        let mut bindings = isolated_bindings();
        let dock = bindings.dock.clone();
        let addresses = bindings.addresses.clone();
        let loopback = loopback_interface();
        let device = BoundDevice::new(loopback.name.clone(), loopback.index).unwrap();
        let snapshot = HashMap::from([(loopback.index, loopback)]);
        // Both unscoped temporary sockets and another owner's device-bound socket survive.
        let foreign = [
            Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()),
            Arc::new(UdpSocket::bind_to_device("127.0.0.1:0".parse().unwrap(), device).unwrap()),
        ];
        for socket in &foreign {
            dock.add(socket.clone()).unwrap().unwrap();
        }
        bindings.scan(&HashMap::new());
        assert_eq!(dock.len(), 2);
        bindings.scan(&snapshot);
        assert_eq!(bindings.bindings.len(), 1);
        let first = bindings.bindings.values().next().unwrap().socket.clone();
        let bound = first.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
        let mut events = addresses.subscribe_punch(Scopes::ALL);
        assert!(
            matches!(events.try_recv().unwrap(), qprotocol::AddressEvent::Added { endpoint, .. } if endpoint == direct)
        );
        bindings.scan(&snapshot);
        assert!(Arc::ptr_eq(&first, &dock.find_socket(bound).unwrap()));
        assert_eq!(bindings.bindings.values().next().unwrap().bound, bound);
        assert!(
            events.try_recv().is_err(),
            "unchanged bindings must not be republished"
        );

        let outer = EndpointAddr::direct("8.8.8.8:4567".parse().unwrap());
        let relay = EndpointAddr::mediate("8.8.4.4:3478".parse().unwrap(), outer.addr());
        for alias in [outer, relay] {
            dock.topology().quic().register(alias, &first).unwrap();
        }
        addresses.insert_outer(&first, outer).unwrap();
        addresses.set_nat(bound, qbase::net::NatType::RestrictedCone);
        bindings.scan(&HashMap::new());
        assert!(dock.find_socket(bound).is_none());
        assert!(addresses.mdns_endpoints(bound).is_empty());
        assert!(addresses.ddns_endpoints().is_empty());
        assert_eq!(addresses.nat(bound), None);
        for alias in [direct, outer, relay] {
            assert!(dock.topology().quic().find_socket(alias).is_none());
        }
        let mut removed = false;
        while let Ok(event) = events.try_recv() {
            removed |= matches!(event, qprotocol::AddressEvent::BoundRemoved { bound: candidate } if candidate == bound);
        }
        assert!(removed);
        bindings.scan(&snapshot);
        assert_eq!(bindings.bindings.len(), 1);
        let replacement = bindings.bindings.values().next().unwrap().bound;
        assert_ne!(bound, replacement);
        drop(bindings);
        assert!(addresses.mdns_endpoints(replacement).is_empty());
        assert!(dock.find_socket(replacement).is_none());
        for socket in &foreign {
            assert!(Arc::ptr_eq(
                socket,
                &dock.find_socket(socket.local_addr().unwrap()).unwrap()
            ));
        }
    }

    #[tokio::test]
    async fn scan_rebinds_when_interface_identity_changes() {
        let mut bindings = isolated_bindings();
        let loopback = loopback_interface();
        let snapshot = HashMap::from([(loopback.index, loopback.clone())]);
        bindings.scan(&snapshot);
        let original = bindings.bindings.values().next().unwrap().socket.clone();
        let bound = original.local_addr().unwrap();
        // A new device may reuse both index and name; hardware identity still changes.
        let mut changed = loopback.clone();
        changed.hw_addr.push_str("-replaced");
        bindings.scan(&HashMap::from([(changed.index, changed)]));
        assert_eq!(bindings.bindings.len(), 1);
        assert!(bindings.dock.find_socket(bound).is_none());
        assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
        let replacement = bindings.bindings.values().next().unwrap().socket.clone();
        assert!(!Arc::ptr_eq(&original, &replacement));

        let mut changed = loopback;
        changed.index = u32::MAX;
        bindings.scan(&HashMap::from([(changed.index, changed)]));
        assert!(
            bindings.bindings.is_empty(),
            "invalid interface cannot bind"
        );
        assert!(
            bindings
                .addresses
                .mdns_endpoints(replacement.local_addr().unwrap())
                .is_empty()
        );
        bindings.scan(&snapshot);
        assert_eq!(bindings.bindings.len(), 1);
    }

    #[tokio::test]
    async fn registration_preserves_existing_owners_and_rolls_back_failed_publication() {
        let bindings = isolated_bindings();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let bound = socket.local_addr().unwrap();
        let direct = EndpointAddr::direct(bound);
        bindings.dock.add(socket.clone()).unwrap().unwrap();
        assert!(bindings.register(socket.clone()).unwrap().is_none());
        assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
        assert!(bindings.dock.find_socket(bound).is_some());
        bindings.dock.remove(&socket);
        bindings.addresses.insert_inner(&socket, direct).unwrap();
        assert!(bindings.register(socket.clone()).is_err());
        assert!(bindings.dock.find_socket(bound).is_none());
        assert!(
            bindings
                .dock
                .topology()
                .quic()
                .find_socket(direct)
                .is_none()
        );
        assert_eq!(bindings.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
        bindings.addresses.remove_bound(bound);
        let registration = bindings.register(socket).unwrap().unwrap();
        assert_eq!(bindings.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
        bindings.withdraw(&registration);
    }

    #[tokio::test]
    async fn scan_withdraws_and_rebinds_after_receiver_exit_or_abort() {
        use qbase::{datagram::forward::Payload, net::route::Pathway};
        for abort in [false, true] {
            let mut bindings = isolated_bindings();
            let loopback = loopback_interface();
            let snapshot = HashMap::from([(loopback.index, loopback)]);
            bindings.scan(&snapshot);
            let binding = bindings.bindings.values().next().unwrap();
            let socket = binding.socket.clone();
            let bound = binding.bound;
            let receiver = binding.receiver.clone();
            if abort {
                receiver.abort();
            } else {
                // Force a real receive-loop error by forwarding IPv6 through IPv4.
                bindings.dock.topology().forward().serve(bound, &socket);
                let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let pathway = Pathway::new(
                    EndpointAddr::direct("[::1]:12345".parse().unwrap()),
                    EndpointAddr::direct("[::1]:9".parse().unwrap()),
                );
                let offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
                let mut bytes = bytes::BytesMut::zeroed(offset + 1);
                bytes[offset] = 0x40;
                let packet = Payload::from_raw(&pathway, bytes, offset).unwrap();
                peer.send_to(packet.as_ref(), bound).await.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while !receiver.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(
                !bindings.addresses.mdns_endpoints(bound).is_empty(),
                "Dock leaves publication to Network"
            );
            bindings.scan(&snapshot);
            assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
            assert!(bindings.dock.find_socket(bound).is_none());
            assert_eq!(bindings.bindings.len(), 1);
            assert_ne!(bindings.bindings.values().next().unwrap().bound, bound);
        }
    }
}
