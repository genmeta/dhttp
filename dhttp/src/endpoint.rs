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

// Implementation fragments share this module and its frozen private resources.
include!("endpoint/api.rs");
include!("endpoint/request.rs");
include!("endpoint/network.rs");
include!("endpoint/connection.rs");
include!("endpoint/service.rs");
include!("endpoint/body.rs");
include!("endpoint/bindings.rs");

#[cfg(test)]
#[path = "../tests/unit/endpoint.rs"]
mod tests;
