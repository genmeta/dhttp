//! Connection pool identity, outgoing handshakes and bidirectional request driving.
use super::DhttpNetwork;
use crate::{Endpoint, Error, Result, endpoint::handle_request, transport::QuicTransport};
use qrecovery::{recv::StopSending, send::CancelStream};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

#[derive(Clone)]
pub(super) enum ConnectionKey {
    Incoming {
        local: Arc<str>,
        remote: Option<Arc<str>>,
    },
    Outgoing {
        local: Option<Endpoint>,
        remote: Arc<str>,
    },
}

impl ConnectionKey {
    fn names(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Incoming { local, remote } => (Some(local), remote.as_deref()),
            Self::Outgoing { local, remote } => (local.as_ref().map(Endpoint::name), Some(remote)),
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

pub(super) type H3 = h3x::H3Connection<QuicTransport>;

pub(super) async fn serve_connection(network: &'static DhttpNetwork, key: ConnectionKey, h3: H3) {
    let name: Option<Arc<str>> = key.names().0.map(Arc::from);
    loop {
        let (mut writer, mut reader) = match h3.accept_bi().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(endpoint = ?name.as_deref(), %error, "stopped accepting HTTP/3 streams");
                break;
            }
        };
        tracing::trace!(
            local = ?key.names().0,
            remote = ?key.names().1,
            stream_id = writer.stream_id(),
            paths = ?h3.transport().connection.validated_paths(),
            "HTTP/3 request validated QUIC paths"
        );
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

pub(super) async fn connect(key: ConnectionKey) -> Result<H3> {
    let ConnectionKey::Outgoing { local, remote } = &key else {
        return Err(Error::InvalidRequest {
            message: "cannot initiate a connection with an incoming key".into(),
        });
    };
    let network = DhttpNetwork::global()?;
    tracing::trace!(local = ?key.names().0, remote = ?key.names().1, "outgoing QUIC handshake started");
    let (local, remote, connection) = match local {
        Some(endpoint) => {
            let mut quic = qconn::QuicEndpoint::from(endpoint.identity.clone());
            quic.set_alpn(vec![h3x::ALPN.to_vec()]);
            quic.connect(remote.to_string()).await?
        }
        None => {
            let mut quic = qconn::QuicEndpoint::anonymous();
            quic.set_alpn(vec![h3x::ALPN.to_vec()]);
            quic.connect(remote.to_string()).await?
        }
    };
    tracing::trace!(
        local = ?local.as_ref().map(qtls::LocalAuthority::name),
        remote = %remote.name(),
        paths = ?connection.validated_paths(),
        "outgoing QUIC handshake completed"
    );
    let transport = QuicTransport::new(connection, local, Some(remote), h3x::Role::Client)?;
    let h3 = H3::new(transport, h3x::Settings::default())?;
    tokio::spawn(serve_connection(network, key, h3.clone()));
    Ok(h3)
}

#[cfg(test)]
#[path = "../../tests/unit/network/connection.rs"]
mod tests;
