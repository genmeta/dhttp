//! Endpoint, network ownership, and standard-body adaptation.
// These private resources share one module so no extra cross-module lifecycle API is needed.
use crate::{Body, BoxError, EmptyBody, Error, RequestFuture, Result, transport::QuicTransport};
use bytes::Bytes;
use h3x::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use qbase::net::addr::EndpointAddr;
use qconn::{BelongsTo, Scope, Scopes};
use qprotocol::{Dock, QuicProtocol, UdpSocket};
use qrecovery::{recv::StopSending, send::CancelStream};
use std::{
    collections::HashMap,
    future::IntoFuture,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_service::Service;

type ErasedService =
    tower::util::BoxCloneService<http::Request<Body>, http::Response<Body>, BoxError>;
type ConnectionKey = (Arc<str>, Arc<str>);
type H3 = h3x::H3Connection<QuicTransport>;
static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(16 * 60);
const BODY_WINDOW_BYTES: usize = 64 * 1024;
const BODY_READ_CHUNK_BYTES: usize = 16 * 1024;
const ACCEPT_QUEUE_CAPACITY: usize = 64;

#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

#[must_use = "configure and await the request to send it"]
pub struct Request<B> {
    endpoint: Endpoint,
    message: http::Request<B>,
}

#[derive(Clone)]
pub struct NetworkConfig {
    pub listen: Vec<ListenConfig>,
}
#[derive(Clone)]
pub enum ListenConfig {
    Scope(Scopes),
    Interface { device: String, scopes: Scopes },
}

pub struct DhttpNetwork {
    config: NetworkConfig,
    endpoints: Mutex<HashMap<Arc<str>, Arc<EndpointConnections>>>,
    listeners: Mutex<HashMap<Arc<str>, Arc<ListenerRegistration>>>,
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
    bindings: Mutex<HashMap<(String, IpAddr), Binding>>,
    addresses: qprotocol::AddressBook,
    stop: CancellationToken,
}
struct EndpointConnections {
    stop: CancellationToken,
    connections: Mutex<Vec<H3>>,
}
struct Binding {
    socket: Arc<UdpSocket>,
    scopes: Scopes,
    device_index: u32,
}
struct ListenerRegistration {
    service: Mutex<ErasedService>,
    stop: CancellationToken,
    qconn_owner: Arc<qconn::Server>,
}

impl Endpoint {
    pub async fn load(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: Arc::from(dhttp_home::normalize_name(name.as_ref()).ok_or_else(|| {
                Error::InvalidName {
                    name: name.as_ref().to_owned(),
                }
            })?),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn get(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::GET, uri)
    }
    pub fn head(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::HEAD, uri)
    }
    pub fn post(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::POST, uri)
    }
    pub fn put(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PUT, uri)
    }
    pub fn patch(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PATCH, uri)
    }
    pub fn delete(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::DELETE, uri)
    }
    pub fn options(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::OPTIONS, uri)
    }
    pub fn request(&self, method: http::Method, uri: http::Uri) -> Request<EmptyBody> {
        let mut message = http::Request::new(EmptyBody::new());
        *message.method_mut() = method;
        *message.uri_mut() = uri;
        self.from_request(message)
    }
    pub fn from_request<B>(&self, request: http::Request<B>) -> Request<B> {
        Request {
            endpoint: self.clone(),
            message: request,
        }
    }

    pub async fn listen<S, B>(&self, scopes: Scopes, service: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let network = DhttpNetwork::global()?;
        for scope in [Scope::Loopback, Scope::Internal, Scope::External] {
            if scopes.contains(scope)
                && !network.config.listen.iter().any(|rule| match rule {
                    ListenConfig::Scope(allowed)
                    | ListenConfig::Interface {
                        scopes: allowed, ..
                    } => allowed.contains(scope),
                })
            {
                return Err(Error::InvalidNetworkConfig {
                    message:
                        "listener scope exceeds startup network configuration; restart is required"
                            .into(),
                });
            }
        }
        let quic = quic_endpoint(&self.name).await?;
        let (lifetime, dropped) = tokio::sync::oneshot::channel::<()>();
        let owner = endpoint_connections(network, &self.name);
        let stop = owner.stop.child_token();
        let (accepted, receiving) = tokio::sync::mpsc::channel(ACCEPT_QUEUE_CAPACITY);
        let service = service
            .map_err(Into::into)
            .map_response(|response| response.map(|body| body.map_err(Into::into).boxed_unsync()))
            .boxed_clone();
        let supervisor = {
            let _connections = owner.connections.lock().unwrap();
            let mut listeners = network.listeners.lock().unwrap();
            check_open(network, &owner)?;
            if listeners.contains_key(&self.name) {
                return Err(Error::AlreadyListening);
            }
            if qconn::ServerRegistry::global().get(&self.name).is_some() {
                return Err(Error::NameInUse {
                    name: self.name.to_string(),
                });
            }
            let callback_stop = stop.clone();
            let callback_owner = owner.clone();
            let callback_name = self.name.clone();
            quic.listen(scopes, move |result| {
                // Capture the actual identity and listening lifetime at registration time.
                let _connections = callback_owner.connections.lock().unwrap();
                let listeners = network.listeners.lock().unwrap();
                if callback_stop.is_cancelled()
                    || check_open(network, &callback_owner).is_err()
                    || !listeners.contains_key(&callback_name)
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
            let qconn_owner = qconn::ServerRegistry::global()
                .get(&self.name)
                .ok_or(Error::NetworkUnavailable)?;
            let registration = Arc::new(ListenerRegistration {
                service: Mutex::new(service),
                stop,
                qconn_owner,
            });
            listeners.insert(self.name.clone(), registration.clone());
            tokio::spawn(listen_supervisor(
                network,
                self.name.clone(),
                owner.clone(),
                registration,
                receiving,
                dropped,
            ))
        };
        // This Sender must stay alive across the await. Dropping the public future
        // closes the channel, leaving the supervisor responsible for withdrawal.
        let result = supervisor.await.map_err(io_error)?;
        drop(lifetime);
        result
    }

    pub fn stop_listening(&self) -> Result<()> {
        let network = DhttpNetwork::global()?;
        let owner = endpoint_connections(network, &self.name);
        let _connections = owner.connections.lock().unwrap();
        let mut listeners = network.listeners.lock().unwrap();
        if let Some(registration) = listeners.remove(&self.name) {
            registration.stop.cancel();
            withdraw_listener(&self.name, &registration);
        }
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let network = DhttpNetwork::global()?;
        close_endpoint(network, &self.name)
    }
}

impl<B> Request<B> {
    pub fn header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().insert(name, value);
        self
    }
    pub fn append_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().append(name, value);
        self
    }
    pub fn body<T>(self, body: T) -> Request<T> {
        let (parts, _) = self.message.into_parts();
        Request {
            endpoint: self.endpoint,
            message: http::Request::from_parts(parts, body),
        }
    }
}
impl<B> IntoFuture for Request<B>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Output = Result<http::Response<Body>>;
    type IntoFuture = RequestFuture;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let network = DhttpNetwork::global()?;
            let owner = endpoint_connections(network, &self.endpoint.name);
            let mut message = self.message;
            *message.uri_mut() = canonical_uri(&self.endpoint, message.uri())?;
            let remote = remote_name(message.uri())?;
            let h3 =
                get_connection(network, self.endpoint.name.clone(), remote, owner.clone()).await?;
            let (writer, reader) = tokio::select! {
                _ = owner.stop.cancelled() => return Err(Error::EndpointClosed),
                result = tokio::time::timeout(OPERATION_TIMEOUT, h3.open_bi()) => result.map_err(io_error)?.map_err(h3_error)?,
            };
            send_request(
                message,
                writer,
                reader,
                h3.qpack().clone(),
                owner.stop.clone(),
            )
            .await
        })
    }
}

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

async fn quic_endpoint(name: &str) -> Result<qconn::QuicEndpoint> {
    let mut endpoint = qconn::QuicEndpoint::new(crate::home::load_identity(name).await?);
    endpoint.set_alpn(vec![h3x::ALPN.to_vec()]);
    Ok(endpoint)
}
fn canonical_uri(endpoint: &Endpoint, uri: &http::Uri) -> Result<http::Uri> {
    let name =
        dhttp_identity::name::DhttpName::try_from(endpoint.name().to_owned()).map_err(|error| {
            Error::InvalidRequest {
                message: error.to_string(),
            }
        })?;
    name.expand_uri(uri.clone())
        .map_err(|error| Error::InvalidRequest {
            message: error.to_string(),
        })
}
fn remote_name(uri: &http::Uri) -> Result<Arc<str>> {
    if let Some(scheme) = uri.scheme_str() {
        if !matches!(scheme, "https" | "http" | "dhttp" | "wss" | "ws") {
            return Err(Error::InvalidRequest {
                message: "unsupported URI scheme".into(),
            });
        }
    }
    let host = uri.host().ok_or_else(|| Error::InvalidRequest {
        message: "URI has no remote authority".into(),
    })?;
    dhttp_home::normalize_name(host)
        .map(Arc::from)
        .ok_or_else(|| Error::InvalidName { name: host.into() })
}
async fn get_connection(
    network: &'static DhttpNetwork,
    local: Arc<str>,
    remote: Arc<str>,
    owner: Arc<EndpointConnections>,
) -> Result<H3> {
    {
        let _connections = owner.connections.lock().unwrap();
        check_open(network, &owner)?;
    }
    let key = (local, remote);
    let connection = tokio::select! {
        _ = owner.stop.cancelled() => return Err(Error::EndpointClosed),
        result = tokio::time::timeout(CONNECT_TIMEOUT, network.pool.get(&key)) => result.map_err(io_error)??,
    };
    let _connections = owner.connections.lock().unwrap();
    if let Err(error) = check_open(network, &owner) {
        network.pool.remove_connection(&key, &connection);
        let _ = connection.close("endpoint closed during connection", 0);
        return Err(error);
    }
    Ok(connection)
}
async fn open_outbound((local_name, remote_name): ConnectionKey) -> Result<H3> {
    let network = DhttpNetwork::global()?;
    let owner = endpoint_connections(network, &local_name);
    let endpoint = quic_endpoint(&local_name).await?;
    // qconn's connect future does not cancel its internal handshake task when
    // dropped. Keep one local delivery driver so a late established connection
    // is explicitly closed if the requesting operation has already gone away.
    let connecting_owner = owner.clone();
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
        if connecting_owner.stop.is_cancelled() {
            return Err(Error::EndpointClosed);
        }
        Ok::<_, Error>(connected)
    });
    let connected = tokio::select! {
        _ = owner.stop.cancelled() => return Err(Error::EndpointClosed),
        result = tokio::time::timeout(CONNECT_TIMEOUT, connecting) => result.map_err(io_error)?.map_err(io_error)??,
    };
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
    {
        let mut connections = owner.connections.lock().unwrap();
        if let Err(error) = check_open(network, &owner) {
            let _ = h3.close("endpoint closed during connection", 0);
            return Err(error);
        }
        connections.push(h3.clone());
        tokio::spawn(serve_connection(
            network,
            local_name,
            owner.clone(),
            h3.clone(),
        ));
    }
    Ok(h3)
}
fn forget_pool_connection(network: &DhttpNetwork, local_name: &Arc<str>, connection: &H3) {
    if let Some(remote) = &connection.transport().handshake.remote {
        network
            .pool
            .remove_connection(&(local_name.clone(), Arc::from(remote.name())), connection);
    }
}

async fn listen_supervisor(
    network: &'static DhttpNetwork,
    name: Arc<str>,
    owner: Arc<EndpointConnections>,
    registration: Arc<ListenerRegistration>,
    mut receiving: tokio::sync::mpsc::Receiver<std::result::Result<qconn::Accepted, qconn::Error>>,
    dropped: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    tokio::pin!(dropped);
    let result = loop {
        let accepted = tokio::select! {
            _ = registration.stop.cancelled() => break Ok(()),
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
        let mut connections = owner.connections.lock().unwrap();
        let listeners = network.listeners.lock().unwrap();
        if check_open(network, &owner).is_err()
            || registration.stop.is_cancelled()
            || !listeners
                .get(&name)
                .is_some_and(|current| Arc::ptr_eq(current, &registration))
        {
            let _ = h3.close("listener stopped before admission", 0);
            continue;
        }
        connections.push(h3.clone());
        if let Some(remote) = &h3.transport().handshake.remote {
            let _ = network
                .pool
                .insert((name.clone(), Arc::from(remote.name())), h3.clone());
        }
        tokio::spawn(serve_connection(network, name.clone(), owner.clone(), h3));
    };
    registration.stop.cancel();
    {
        let _connections = owner.connections.lock().unwrap();
        let mut listeners = network.listeners.lock().unwrap();
        if listeners
            .get(&name)
            .is_some_and(|current| Arc::ptr_eq(current, &registration))
        {
            listeners.remove(&name);
        }
        withdraw_listener(&name, &registration);
    }
    receiving.close();
    while let Some(accepted) = receiving.recv().await {
        if let Ok((_, _, connection)) = accepted {
            connection.close(qbase::varint::VarInt::from_u32(0), "listener stopped");
        }
    }
    result
}

async fn serve_connection(
    network: &'static DhttpNetwork,
    name: Arc<str>,
    owner: Arc<EndpointConnections>,
    h3: H3,
) {
    let mut exchanges = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = owner.stop.cancelled() => break,
            _ = exchanges.join_next(), if !exchanges.is_empty() => {},
            accepted = h3.accept_bi() => {
                let (mut writer, mut reader) = match accepted { Ok(value) => value, Err(_) => break };
                let app = {
                    let _connections = owner.connections.lock().unwrap();
                    let listeners = network.listeners.lock().unwrap();
                    if check_open(network, &owner).is_ok() {
                        listeners.get(&name).filter(|entry| !entry.stop.is_cancelled())
                            .map(|entry| entry.service.lock().unwrap().clone())
                    } else { None }
                };
                let Some(app) = app else {
                    reader.stop(h3x::ErrorCode::RequestRejected.as_u64());
                    writer.cancel(h3x::ErrorCode::RequestRejected.as_u64());
                    continue;
                };
                let qpack = h3.qpack().clone();
                let handshake = h3.transport().handshake.clone();
                let stop = owner.stop.clone();
                let serving = serve_exchange(app, writer, reader, qpack, handshake);
                exchanges.spawn(async move {
                    tokio::select! {
                        _ = stop.cancelled() => {},
                        _ = serving => {},
                    }
                });
            }
        }
    }
    exchanges.abort_all();
    while exchanges.join_next().await.is_some() {}
    {
        let mut connections = owner.connections.lock().unwrap();
        connections.retain(|current| {
            !Arc::ptr_eq(&current.transport().connection, &h3.transport().connection)
        });
    }
    forget_pool_connection(network, &name, &h3);
    let _ = h3.close("connection receiver ended", 0);
}

fn serve_exchange<W, R>(
    app: ErasedService,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
    handshake: Arc<qtls::HandshakeSummary>,
) -> impl std::future::Future<Output = Result<()>>
where
    W: WriteResponse + CancelStream,
    R: ReadRequest,
{
    // Establish cancellation ownership before the future is polled.
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    async move {
        let reading = reader.read_request(qpack.clone());
        tokio::pin!(reading);
        let writer = writer;
        let incoming = tokio::time::timeout(OPERATION_TIMEOUT, &mut reading)
            .await
            .map_err(io_error)?
            .map_err(h3_error)?;
        let (mut parts, inbound) = incoming.into_parts();
        let method = parts.method.clone();
        let trailers = parts
            .extensions
            .remove::<h3x::Trailers>()
            .unwrap_or_default();
        parts.extensions.insert((*handshake).clone());
        let body = receiving_body(inbound, trailers, h3x::ErrorCode::NoError);
        let request: http::Request<Body> = http::Request::from_parts(parts, body);
        let mut app = app;
        futures::future::poll_fn(|cx| app.poll_ready(cx))
            .await
            .map_err(box_error)?;
        let response: std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<http::Response<Body>, BoxError>,
                    > + Send,
            >,
        > = app.call(request);
        let response = response.await.map_err(box_error)?;
        send_response(
            response,
            method,
            scopeguard::ScopeGuard::into_inner(writer),
            qpack,
        )
        .await
    }
}

fn receiving_body(
    inbound: h3x::ArcWndBuf,
    trailers: h3x::Trailers,
    drop_code: h3x::ErrorCode,
) -> Body {
    // Construct before the generator: dropping an entirely unpolled Body must stop native input too.
    let guard = scopeguard::guard(inbound, move |mut body| body.stop(drop_code.as_u64()));
    StreamBody::new(async_stream::try_stream! {
        let mut guard = guard;
        loop {
            let mut bytes = vec![0; BODY_READ_CHUNK_BYTES];
            let count = tokio::time::timeout(OPERATION_TIMEOUT, guard.read(&mut bytes)).await.map_err(io_error)?.map_err(io_error)?;
            if count == 0 { break; }
            bytes.truncate(count);
            yield Frame::data(Bytes::from(bytes));
        }
        scopeguard::ScopeGuard::into_inner(guard);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    }).map_err(|error: Error| Box::new(error) as BoxError).boxed_unsync()
}

async fn pump_body<B>(
    body: B,
    mut native: h3x::ArcWndBuf,
    mut trailer: impl FnMut(http::HeaderName, http::HeaderValue),
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let mut body = Box::pin(body);
    loop {
        let frame: Option<std::result::Result<Frame<Bytes>, BoxError>> =
            tokio::time::timeout(OPERATION_TIMEOUT, body.frame())
                .await
                .map_err(io_error)?
                .map(|frame| frame.map_err(Into::into));
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(box_error)?;
        match frame.into_data() {
            Ok(data) => {
                tokio::time::timeout(OPERATION_TIMEOUT, native.write_bytes(data))
                    .await
                    .map_err(io_error)?
                    .map_err(io_error)?;
            }
            Err(frame) => {
                if let Ok(fields) = frame.into_trailers() {
                    // HeaderMap's borrowed iterator emits the name for every value.
                    for (name, value) in fields.iter() {
                        trailer(name.clone(), value.clone());
                    }
                }
            }
        }
    }
    native.shutdown().await.map_err(io_error)
}

fn send_response<B, W>(
    response: http::Response<B>,
    method: http::Method,
    writer: W,
    qpack: h3x::ArcQpack,
) -> impl std::future::Future<Output = Result<()>>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
    W: WriteResponse + CancelStream,
{
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    async move {
        let (parts, body) = response.into_parts();
        let suppressed = method == http::Method::HEAD
            || parts.status == http::StatusCode::NO_CONTENT
            || parts.status == http::StatusCode::NOT_MODIFIED;
        let body = if suppressed {
            drop(body);
            None
        } else {
            Some(body)
        };
        let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
        let outgoing = h3x::Response::<h3x::W>::from_parts(parts, buffer.clone());
        let trailers = outgoing.clone();
        let writing =
            scopeguard::ScopeGuard::into_inner(writer).write_response(outgoing, method, qpack);
        tokio::pin!(writing);
        // This guard is declared after the pinned writer and therefore cancels
        // the native body before dropping the writer future on any exit.
        let guard = scopeguard::guard(trailers.clone(), |mut response| {
            response.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
        });
        if let Some(body) = body {
            let pumping = pump_body(body, buffer, move |name, value| {
                trailers.append_trailer(name, value);
            });
            // Poll the writer first so its existing body cancellation callback
            // is installed before a producer can fail on its first frame.
            tokio::try_join!(biased; async { (&mut writing).await.map_err(h3_error) }, pumping)?;
        } else {
            writing.await.map_err(h3_error)?;
        }
        scopeguard::ScopeGuard::into_inner(guard);
        Ok(())
    }
}

async fn send_request<B, W, R>(
    message: http::Request<B>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
    stop: CancellationToken,
) -> Result<http::Response<Body>>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    W: WriteRequest + CancelStream + 'static,
    R: ReadResponse,
{
    let method = message.method().clone();
    let (mut parts, body) = message.into_parts();
    // Forwarded trusted identities never affect this endpoint's outbound authentication.
    parts.extensions.remove::<qtls::HandshakeSummary>();
    parts.extensions.remove::<qtls::LocalAuthority>();
    parts.extensions.remove::<qtls::RemoteAuthority>();
    let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
    let outgoing = h3x::Request::<h3x::W>::from_parts(parts, buffer.clone());
    let response_cancel = outgoing.clone();
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    let send_qpack = qpack.clone();
    let send_stop = stop.clone();
    let upload = tokio::spawn(async move {
        if send_stop.is_cancelled() {
            return Err(Error::EndpointClosed);
        }
        let trailers = outgoing.clone();
        let writing =
            scopeguard::ScopeGuard::into_inner(writer).write_request(outgoing, send_qpack);
        tokio::pin!(writing);
        let guard = scopeguard::guard(trailers.clone(), |mut request| {
            request.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
        });
        let pumping = pump_body(body, buffer, move |name, value| {
            trailers.append_trailer(name, value);
        });
        tokio::select! {
            biased;
            result = async { tokio::try_join!(biased; async { (&mut writing).await.map_err(h3_error) }, pumping) } => { result?; }
            _ = send_stop.cancelled() => return Err(Error::EndpointClosed),
        }
        scopeguard::ScopeGuard::into_inner(guard);
        Ok(())
    });
    let mut upload = scopeguard::guard(upload, |task| task.abort());
    let reading = reader.read_response(method, qpack);
    tokio::pin!(reading);
    let response_cancel = scopeguard::guard(response_cancel, |mut request| {
        request.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
    });
    let timeout = tokio::time::timeout(OPERATION_TIMEOUT, &mut reading);
    tokio::pin!(timeout);
    // A completed upload is not a prerequisite for returning response headers.
    let mut completed = false;
    let response = loop {
        tokio::select! {
            _ = stop.cancelled() => return Err(Error::EndpointClosed),
            result = &mut *upload, if !completed => { upload_result(result.map_err(io_error)?)?; completed = true; },
            response = &mut timeout => break response.map_err(io_error)?.map_err(h3_error)?,
        }
    };
    let (mut parts, inbound) = response.into_parts();
    let trailers = parts
        .extensions
        .remove::<h3x::Trailers>()
        .unwrap_or_default();
    let native = scopeguard::guard(inbound, |mut body| {
        body.stop(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    let stream = async_stream::try_stream! {
        let mut native = native;
        let mut upload = upload;
        loop {
            let mut bytes = vec![0; BODY_READ_CHUNK_BYTES];
            let count = async {
                let reading = tokio::time::timeout(OPERATION_TIMEOUT, native.read(&mut bytes));
                tokio::pin!(reading);
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => return Err(Error::EndpointClosed),
                        result = &mut *upload, if !completed => { upload_result(result.map_err(io_error)?)?; completed = true; },
                        result = &mut reading => return result.map_err(io_error)?.map_err(io_error),
                    }
                }
            }.await?;
            if count == 0 { break; }
            bytes.truncate(count);
            yield Frame::data(Bytes::from(bytes));
        }
        scopeguard::ScopeGuard::into_inner(native);
        // EOF completes receiving. Upload may continue independently until its own EOF.
        scopeguard::ScopeGuard::into_inner(upload);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    };
    let body = StreamBody::new(stream)
        .map_err(|error: Error| Box::new(error) as BoxError)
        .boxed_unsync();
    scopeguard::ScopeGuard::into_inner(response_cancel);
    Ok(http::Response::from_parts(parts, body))
}

pub async fn resolve_remote(endpoint: &Endpoint, name: &str) -> Result<qtls::RemoteAuthority> {
    let network = DhttpNetwork::global()?;
    let remote = dhttp_home::normalize_name(name)
        .map(Arc::from)
        .ok_or_else(|| Error::InvalidName {
            name: name.to_owned(),
        })?;
    let owner = endpoint_connections(network, &endpoint.name);
    let connection = get_connection(network, endpoint.name.clone(), remote, owner).await?;
    connection
        .transport()
        .handshake
        .remote
        .clone()
        .ok_or_else(|| Error::InvalidRequest {
            message: "peer has no authenticated authority".into(),
        })
}
// A server may decline further upload with H3_NO_ERROR while still returning
// a valid response. Both the native writer and the body pump can observe it.
fn upload_result(result: Result<()>) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if cause
            .downcast_ref::<h3x::Error>()
            .is_some_and(|error| error.code == h3x::ErrorCode::NoError)
        {
            return Ok(());
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                cause = inner;
                continue;
            }
        }
        match cause.source() {
            Some(source) => cause = source,
            None => break,
        }
    }
    Err(error)
}
fn h3_error(source: h3x::Error) -> Error {
    Error::Http3 {
        source: Arc::new(source),
    }
}
fn quic_error(source: qconn::Error) -> Error {
    Error::Quic {
        source: Arc::new(source),
    }
}
fn io_error(source: impl Into<BoxError>) -> Error {
    Error::Io {
        source: Arc::new(std::io::Error::other(source.into())),
    }
}
fn box_error(source: BoxError) -> Error {
    Error::Io {
        source: Arc::new(std::io::Error::other(source)),
    }
}

fn clear_bindings(network: &DhttpNetwork) {
    let mut bindings = network.bindings.lock().unwrap();
    for (_, binding) in bindings.drain() {
        withdraw_binding(network, binding);
    }
}
fn withdraw_binding(network: &DhttpNetwork, binding: Binding) {
    if let Ok(actual) = binding.socket.local_addr() {
        network.addresses.remove_bound(actual);
        QuicProtocol::global().unregister(EndpointAddr::direct(actual), &binding.socket);
    }
    Dock::global().remove(&binding.socket);
}
fn update_bindings(network: &DhttpNetwork) {
    let devices = netdev::get_interfaces();
    let mut selected = HashMap::new();
    for rule in &network.config.listen {
        for device in devices.iter().filter(|device| device.is_up()) {
            let scopes = match rule {
                ListenConfig::Scope(scopes) => *scopes,
                ListenConfig::Interface {
                    device: name,
                    scopes,
                } if *name == device.name => *scopes,
                _ => continue,
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
    if network.stop.is_cancelled() {
        return;
    }
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

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
