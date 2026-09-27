//! Process-wide network resources, connections, and listener lifecycle.
use crate::{
    Body, BoxError, Error, Result,
    endpoint::{h3_error, io_error, serve_exchange},
    transport::QuicTransport,
};
use bytes::Bytes;
use qbase::net::addr::EndpointAddr;
use qconn::{BelongsTo, Scope, Scopes};
use qprotocol::{Dock, QuicProtocol, UdpSocket};
use qrecovery::{recv::StopSending, send::CancelStream};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

pub(crate) type ErasedService =
    tower::util::BoxCloneService<http::Request<Body>, http::Response<Body>, BoxError>;
type ConnectionKey = (Arc<str>, Arc<str>);
type H3 = h3x::H3Connection<QuicTransport>;
static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_QUEUE_CAPACITY: usize = 64;

pub struct DhttpNetwork {
    listeners: Mutex<HashMap<Arc<str>, ListenerEntry>>,
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
    bindings: Mutex<HashMap<(String, IpAddr), Binding>>,
    addresses: qprotocol::AddressBook,
}
struct ListenerEntry {
    service: Mutex<ErasedService>,
    shutdown: Option<oneshot::Sender<()>>,
    owner: Arc<qconn::Server>,
    scopes: Scopes,
}
struct Binding {
    socket: Arc<UdpSocket>,
    scopes: Scopes,
    device_index: u32,
}

impl DhttpNetwork {
    pub async fn init() -> Result<&'static Self> {
        if NETWORK.get().is_some() {
            return Err(Error::AlreadyInitialized);
        }
        // A local flag records whether this invocation performed initialization;
        // no process-level counter or second initialization flag is retained.
        let initialized = std::sync::atomic::AtomicBool::new(false);
        let network = NETWORK
            .get_or_try_init(|| async {
                crate::trust::initialize()?;
                let network = Self {
                    listeners: Mutex::new(HashMap::new()),
                    pool: h3x::Pool::new(open_outbound),
                    bindings: Mutex::new(HashMap::new()),
                    addresses: qprotocol::AddressBook::new(),
                };
                initialized.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok::<_, Error>(network)
            })
            .await?;
        if !initialized.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::AlreadyInitialized);
        }
        let router = qtransport::router::QuicRouter::global().clone();
        QuicProtocol::global().on_receive(move |bytes, pathway, link| {
            let admitted = network.bindings.lock().unwrap().values().any(|binding| {
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
        Ok(network)
    }
    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
    }
}

pub(super) fn withdraw_listener(name: &str, owner: &Arc<qconn::Server>) {
    let registry = qconn::ServerRegistry::global();
    if registry
        .get(name)
        .is_some_and(|current| Arc::ptr_eq(&current, owner))
    {
        registry.remove(name);
    }
}

fn withdraw_binding(network: &DhttpNetwork, binding: Binding) {
    if let Ok(actual) = binding.socket.local_addr() {
        network.addresses.remove_bound(actual);
        QuicProtocol::global().unregister(EndpointAddr::direct(actual), &binding.socket);
    }
    Dock::global().remove(&binding.socket);
}

pub(super) fn update_bindings(network: &DhttpNetwork) {
    // Keep the registration snapshot stable through binding changes so a
    // concurrent start or stop cannot apply an older selection last.
    let listeners = network.listeners.lock().unwrap();
    let scopes = listeners
        .values()
        .filter(|entry| entry.shutdown.is_some())
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
    let mut bindings = network.bindings.lock().unwrap();
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
            let _ = network.addresses.insert_inner(actual, endpoint);
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
        service: ErasedService,
    ) -> Result<()> {
        let quic = quic_endpoint(&name).await?;
        let (lifetime, dropped) = tokio::sync::oneshot::channel::<()>();
        let (shutdown, stopping) = oneshot::channel();
        let (accepted, receiving) = tokio::sync::mpsc::channel(ACCEPT_QUEUE_CAPACITY);
        let supervisor = {
            let mut listeners = self.listeners.lock().unwrap();
            if listeners.contains_key(&name) {
                return Err(Error::AlreadyListening);
            }
            if qconn::ServerRegistry::global().get(&name).is_some() {
                return Err(Error::NameInUse {
                    name: name.to_string(),
                });
            }
            let callback_name = name.clone();
            quic.listen(scopes, move |result| {
                // Reject callbacks from a stopped listening lifetime.
                let listeners = self.listeners.lock().unwrap();
                if !listeners
                    .get(&callback_name)
                    .is_some_and(|entry| entry.shutdown.is_some())
                {
                    if let Ok((_, _, connection)) = result {
                        connection.close(qbase::varint::VarInt::from_u32(0), "listener stopped");
                    }
                    return;
                }
                if let Err(rejected) = accepted.try_send(result) {
                    if let Ok((_, _, connection)) = rejected.into_inner() {
                        connection.close(
                            qbase::varint::VarInt::from_u32(0),
                            "accept queue unavailable",
                        );
                    }
                }
            })
            .map_err(quic_error)?;
            let owner = qconn::ServerRegistry::global()
                .get(&name)
                .ok_or(Error::NetworkUnavailable)?;
            listeners.insert(
                name.clone(),
                ListenerEntry {
                    service: Mutex::new(service),
                    shutdown: Some(shutdown),
                    owner,
                    scopes,
                },
            );
            tokio::spawn(listen_supervisor(self, name, stopping, receiving, dropped))
        };
        update_bindings(self);
        // Dropping the caller's future closes this channel; the supervisor withdraws the listener.
        let result = supervisor.await.map_err(io_error)?;
        drop(lifetime);
        result
    }

    pub(crate) fn stop_listening(&self, name: &str) {
        {
            let mut listeners = self.listeners.lock().unwrap();
            if let Some(entry) = listeners.get_mut(name) {
                if let Some(shutdown) = entry.shutdown.take() {
                    let _ = shutdown.send(());
                }
                withdraw_listener(name, &entry.owner);
            }
        }
        update_bindings(self);
    }

    pub(crate) async fn get_connection(
        &'static self,
        local: Arc<str>,
        remote: Arc<str>,
    ) -> Result<H3> {
        let key = (local, remote);
        tokio::time::timeout(CONNECT_TIMEOUT, self.pool.get(&key))
            .await
            .map_err(io_error)?
    }

    pub(crate) async fn resolve_remote(
        &'static self,
        local: Arc<str>,
        name: &str,
    ) -> Result<qtls::RemoteAuthority> {
        let remote = dhttp_home::normalize_name(name)
            .map(Arc::from)
            .ok_or_else(|| Error::InvalidName {
                name: name.to_owned(),
            })?;
        let connection = self.get_connection(local, remote).await?;
        connection
            .transport()
            .handshake
            .remote
            .clone()
            .ok_or_else(|| Error::InvalidRequest {
                message: "peer has no authenticated authority".into(),
            })
    }
}

async fn quic_endpoint(name: &str) -> Result<qconn::QuicEndpoint> {
    let mut endpoint = qconn::QuicEndpoint::new(crate::home::load_identity(name).await?);
    endpoint.set_alpn(vec![h3x::ALPN.to_vec()]);
    Ok(endpoint)
}

async fn open_outbound((local_name, remote_name): ConnectionKey) -> Result<H3> {
    let network = DhttpNetwork::global()?;
    let endpoint = quic_endpoint(&local_name).await?;
    // qconn's connect future does not cancel its internal handshake task when
    // dropped. Keep one local delivery driver so a late established connection
    // is explicitly closed if the requesting operation has already gone away.
    let connecting = tokio::spawn(async move {
        let connected = endpoint
            .connect(remote_name.to_string())
            .await
            .map_err(quic_error)?;
        let connected = scopeguard::guard(connected, |(_, _, connection)| {
            connection.close(
                qbase::varint::VarInt::from_u32(0),
                "connection recipient cancelled",
            );
        });
        Ok::<_, Error>(connected)
    });
    let connected = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(io_error)?
        .map_err(io_error)??;
    let (local, remote, connection) = scopeguard::ScopeGuard::into_inner(connected);
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
    let h3 = h3x::H3Connection::new(transport, h3x::Settings::default()).map_err(|error| {
        (*connection)
            .clone()
            .close(qbase::varint::VarInt::from_u32(0), "HTTP/3 setup failed");
        h3_error(error)
    })?;
    tokio::spawn(serve_connection(network, local_name, h3.clone()));
    Ok(h3)
}

fn forget_pool_connection(network: &DhttpNetwork, local_name: &Arc<str>, connection: &H3) {
    if let Some(remote) = &connection.transport().handshake.remote {
        network
            .pool
            .remove_connection(&(local_name.clone(), Arc::from(remote.name())), connection);
    }
}

fn quic_error(source: qconn::Error) -> Error {
    Error::Quic {
        source: Arc::new(source),
    }
}

async fn listen_supervisor(
    network: &'static DhttpNetwork,
    name: Arc<str>,
    stopping: oneshot::Receiver<()>,
    mut receiving: tokio::sync::mpsc::Receiver<std::result::Result<qconn::Accepted, qconn::Error>>,
    dropped: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    tokio::pin!(dropped, stopping);
    let result = loop {
        let accepted = tokio::select! {
            _ = &mut stopping => break Ok(()),
            _ = &mut dropped => break Ok(()),
            accepted = receiving.recv() => match accepted { Some(value) => value, None => break Ok(()) },
        };
        let (remote, local, connection) = match accepted {
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
            connection: connection.clone(),
            role: h3x::Role::Server,
        };
        let h3 = match h3x::H3Connection::new(transport, h3x::Settings::default()) {
            Ok(connection) => connection,
            Err(error) => {
                (*connection)
                    .clone()
                    .close(qbase::varint::VarInt::from_u32(0), "HTTP/3 setup failed");
                tracing::debug!(endpoint = %name, %error, "rejected incoming HTTP/3 connection");
                continue;
            }
        };
        let listeners = network.listeners.lock().unwrap();
        if !listeners
            .get(&name)
            .is_some_and(|entry| entry.shutdown.is_some())
        {
            let _ = h3.close("listener stopped before admission", 0);
            continue;
        }
        if let Some(remote) = &h3.transport().handshake.remote {
            let _ = network
                .pool
                .insert((name.clone(), Arc::from(remote.name())), h3.clone());
        }
        tokio::spawn(serve_connection(network, name.clone(), h3));
    };
    receiving.close();
    {
        let mut listeners = network.listeners.lock().unwrap();
        if let Some(entry) = listeners.remove(&name) {
            withdraw_listener(&name, &entry.owner);
        }
    }
    while let Some(accepted) = receiving.recv().await {
        if let Ok((_, _, connection)) = accepted {
            connection.close(qbase::varint::VarInt::from_u32(0), "listener stopped");
        }
    }
    update_bindings(network);
    result
}

async fn serve_connection(network: &'static DhttpNetwork, name: Arc<str>, h3: H3) {
    let mut exchanges = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = exchanges.join_next(), if !exchanges.is_empty() => {},
            accepted = h3.accept_bi() => {
                let (mut writer, mut reader) = match accepted { Ok(value) => value, Err(_) => break };
                let app = {
                    let listeners = network.listeners.lock().unwrap();
                    listeners.get(&name).filter(|entry| entry.shutdown.is_some())
                        .map(|entry| entry.service.lock().unwrap().clone())
                };
                let Some(app) = app else {
                    reader.stop(h3x::ErrorCode::RequestRejected.as_u64());
                    writer.cancel(h3x::ErrorCode::RequestRejected.as_u64());
                    continue;
                };
                let qpack = h3.qpack().clone();
                let handshake = h3.transport().handshake.clone();
                let serving = serve_exchange(app, writer, reader, qpack, handshake);
                exchanges.spawn(serving);
            }
        }
    }
    exchanges.abort_all();
    while exchanges.join_next().await.is_some() {}
    forget_pool_connection(network, &name, &h3);
    let _ = h3.close("connection receiver ended", 0);
}
