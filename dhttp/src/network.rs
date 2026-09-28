//! Process-wide generic h3x connection pool and service registry.
use crate::{
    Body, BoxError, Error, Result,
    endpoint::{h3_error, io_error, serve_exchange},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(not(feature = "tcp-mock"))]
mod quic;
#[cfg(feature = "tcp-mock")]
mod tcp;
#[cfg(not(feature = "tcp-mock"))]
use quic as transport;
#[cfg(feature = "tcp-mock")]
use tcp as transport;

pub(crate) type BoxService =
    tower::util::BoxCloneService<http::Request<Body>, http::Response<Body>, BoxError>;
type ConnectionKey = (Arc<str>, Arc<str>);
type H3 = h3x::H3Connection<transport::H3Transport>;
static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DhttpNetwork {
    listeners: Mutex<HashMap<Arc<str>, transport::ListenerEntry>>,
    pool: h3x::Pool<ConnectionKey, transport::H3Transport, Error>,
    #[cfg(not(feature = "tcp-mock"))]
    transport: transport::Transport,
}

impl DhttpNetwork {
    pub async fn init() -> Result<&'static Self> {
        if NETWORK.get().is_some() {
            return Err(Error::AlreadyInitialized);
        }
        transport::prepare()?;
        NETWORK
            .set(Self {
                listeners: Mutex::new(HashMap::new()),
                pool: h3x::Pool::new(transport::open_outbound),
                #[cfg(not(feature = "tcp-mock"))]
                transport: transport::state(),
            })
            .map_err(|_| Error::AlreadyInitialized)?;
        let network = NETWORK.get().unwrap();
        transport::activate(network);
        Ok(network)
    }

    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
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
        transport::handshake(connection.transport())
            .remote
            .clone()
            .ok_or_else(|| Error::InvalidRequest {
                message: "peer has no authenticated authority".into(),
            })
    }
}

async fn serve_connection(network: &'static DhttpNetwork, name: Arc<str>, h3: H3) {
    while let Ok((writer, reader)) = h3.accept_bi().await {
        let app = network
            .listeners
            .lock()
            .unwrap()
            .get(&name)
            .map(transport::service);
        if let Some(app) = app {
            let qpack = h3.qpack().clone();
            let handshake = transport::handshake(h3.transport());
            tokio::spawn(serve_exchange(app, writer, reader, qpack, handshake));
        }
    }
    transport::forget_pool_connection(network, &name, &h3);
}
