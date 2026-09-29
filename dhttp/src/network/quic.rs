//! QUIC endpoint binding and native stream admission.
use super::*;
use crate::transport::QuicTransport;
use bytes::Bytes;
use qbase::net::addr::EndpointAddr;
use qconn::{BelongsTo, Scope, Scopes};
use qprotocol::{Dock, QuicProtocol, UdpSocket};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

pub(super) type H3Transport = QuicTransport;
pub(super) struct Transport {
    bindings: Mutex<HashMap<(String, IpAddr), Binding>>,
    addresses: qprotocol::AddressBook,
}
pub(super) struct ListenerEntry {
    service: BoxService,
    scopes: Scopes,
}
struct Binding {
    socket: Arc<UdpSocket>,
    scopes: Scopes,
    device_index: u32,
}
pub(super) fn state() -> Transport {
    Transport {
        bindings: Mutex::new(HashMap::new()),
        addresses: qprotocol::AddressBook::new(),
    }
}
pub(super) fn prepare() -> Result<()> {
    crate::trust::initialize()
}
pub(super) fn activate(network: &'static DhttpNetwork) {
    let router = qtransport::router::QuicRouter::global().clone();
    QuicProtocol::global().on_receive(move |bytes, pathway, link| {
        let admitted = network
            .transport
            .bindings
            .lock()
            .unwrap()
            .values()
            .any(|binding| {
                binding.socket.local_addr().ok() == Some(link.dst)
                    && link.src.belongs_to(binding.scopes)
            });
        if admitted {
            router.receive(bytes, pathway, link, 8);
        }
    });
    tokio::spawn(async move {
        let mut updates = tokio::time::interval(Duration::from_secs(2));
        loop {
            updates.tick().await;
            update_bindings(network);
        }
    });
}

pub(super) fn service(entry: &ListenerEntry) -> BoxService {
    entry.service.clone()
}

pub(super) fn handshake(transport: &QuicTransport) -> Arc<qtls::HandshakeSummary> {
    transport.handshake.clone()
}

fn withdraw_binding(network: &DhttpNetwork, binding: Binding) {
    if let Ok(actual) = binding.socket.local_addr() {
        network.transport.addresses.remove_bound(actual);
        QuicProtocol::global().unregister(EndpointAddr::direct(actual), &binding.socket);
    }
    Dock::global().remove(&binding.socket);
}

fn update_bindings(network: &DhttpNetwork) {
    // Keep the registration snapshot stable through binding changes so a
    // concurrent start or stop cannot apply an older selection last.
    let listeners = network.listeners.lock().unwrap();
    let scopes = listeners
        .values()
        .map(|entry| entry.scopes)
        .reduce(|combined, scopes| combined | scopes);
    let devices = netdev::get_interfaces();
    let mut selected = HashMap::new();
    if let Some(scopes) = scopes {
        for device in devices.iter().filter(|device| device.is_up()) {
            for address in device
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .chain(device.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
            {
                if address.is_unspecified() || address.is_multicast() {
                    continue;
                }
                let effective = if device.is_loopback() {
                    if scopes.contains(Scope::Loopback) {
                        Scopes::from(Scope::Loopback)
                    } else {
                        continue;
                    }
                } else {
                    let external = scopes.contains(Scope::External)
                        && !matches!(address, IpAddr::V4(ip) if ip.is_link_local())
                        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local());
                    match (scopes.contains(Scope::Internal), external) {
                        (true, true) => Scope::Internal | Scope::External,
                        (true, false) => Scope::Internal.into(),
                        (false, true) => Scope::External.into(),
                        _ => continue,
                    }
                };
                selected
                    .entry((device.name.clone(), address))
                    .and_modify(|value: &mut (Scopes, u32)| value.0 = value.0 | effective)
                    .or_insert((effective, device.index));
            }
        }
    }
    let mut bindings = network.transport.bindings.lock().unwrap();
    let stale = bindings
        .iter()
        .filter(|(key, value)| selected.get(*key) != Some(&(value.scopes, value.device_index)))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in stale {
        if let Some(binding) = bindings.remove(&key) {
            withdraw_binding(network, binding);
        }
    }
    for ((device, address), (scopes, device_index)) in selected {
        if bindings.contains_key(&(device.clone(), address)) {
            continue;
        }
        let bound = match address {
            IpAddr::V4(ip) => SocketAddr::new(ip.into(), 0),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                ip,
                0,
                0,
                if ip.is_unicast_link_local() {
                    device_index
                } else {
                    0
                },
            )),
        };
        let Ok(bound_device) = qudp::BoundDevice::new(&device, device_index) else {
            continue;
        };
        let Ok(socket) = UdpSocket::bind_to_device(bound, bound_device).map(Arc::new) else {
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
            Dock::global().remove(&socket);
            continue;
        }
        if scopes.contains(Scope::Internal) || scopes.contains(Scope::Loopback) {
            let _ = network.transport.addresses.insert_inner(actual, endpoint);
        }
        bindings.insert(
            (device, address),
            Binding {
                socket,
                scopes,
                device_index,
            },
        );
    }
}

impl DhttpNetwork {
    pub(crate) async fn listen(
        &'static self,
        name: Arc<str>,
        scopes: Scopes,
        service: BoxService,
    ) -> Result<()> {
        let quic = quic_endpoint(&name).await?;
        let (accepted, mut receiving) = tokio::sync::mpsc::unbounded_channel();
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
            quic.listen(scopes, move |result| {
                let _ = accepted.send(result);
            })?;
            listeners.insert(name.clone(), ListenerEntry { service, scopes });
        }
        update_bindings(self);
        let _cleanup = scopeguard::guard(name.clone(), |name| {
            self.listeners.lock().unwrap().remove(&name);
            qconn::ServerRegistry::global().remove(&name);
            update_bindings(self);
        });
        while let Some(result) = receiving.recv().await {
            let (remote, local, connection) = match result {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(endpoint = %name, %error, "rejected incoming QUIC connection");
                    continue;
                }
            };
            let connection = Arc::new(connection);
            let transport = QuicTransport {
                handshake: Arc::new(qtls::HandshakeSummary {
                    alpn: Some(Bytes::copy_from_slice(connection.alpn())),
                    local: Some(local),
                    remote,
                }),
                connection,
                role: h3x::Role::Server,
            };
            let h3 = match h3x::H3Connection::new(transport, h3x::Settings::default()) {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(endpoint = %name, %error, "rejected incoming HTTP/3 connection");
                    continue;
                }
            };
            if let Some(remote) = &h3.transport().handshake.remote {
                let _ = self
                    .pool
                    .insert((name.clone(), Arc::from(remote.name())), h3.clone());
            }
            tokio::spawn(serve_connection(self, name.clone(), h3));
        }
        Ok(())
    }
}

async fn quic_endpoint(name: &str) -> Result<qconn::QuicEndpoint> {
    let mut endpoint = qconn::QuicEndpoint::new(crate::home::load_endpoint(name).await?);
    endpoint.set_alpn(vec![h3x::ALPN.to_vec()]);
    Ok(endpoint)
}

pub(super) async fn open_outbound((local_name, remote_name): ConnectionKey) -> Result<H3> {
    let network = DhttpNetwork::global()?;
    let endpoint = quic_endpoint(&local_name).await?;
    let (local, remote, connection) = endpoint.connect(remote_name.to_string()).await?;
    let connection = Arc::new(connection);
    let transport = QuicTransport {
        handshake: Arc::new(qtls::HandshakeSummary {
            alpn: Some(Bytes::copy_from_slice(connection.alpn())),
            local,
            remote: Some(remote),
        }),
        connection: connection.clone(),
        role: h3x::Role::Client,
    };
    let h3 = h3x::H3Connection::new(transport, h3x::Settings::default())?;
    tokio::spawn(serve_connection(network, local_name, h3.clone()));
    Ok(h3)
}

pub(super) fn forget_pool_connection(
    network: &DhttpNetwork,
    local_name: &Arc<str>,
    connection: &H3,
) {
    if let Some(remote) = &connection.transport().handshake.remote {
        network
            .pool
            .remove_connection(&(local_name.clone(), Arc::from(remote.name())), connection);
    }
}
