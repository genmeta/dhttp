//! Loopback TCP listener and outgoing connection setup for the stream mock.
use super::*;
use crate::transport::tcp::TcpTransport;
use bytes::Bytes;
use qconn::Scopes;

pub(super) type H3Transport = TcpTransport;
pub(super) type ListenerEntry = BoxService;
pub(super) fn prepare() -> Result<()> {
    Ok(())
}
pub(super) fn activate(_: &'static DhttpNetwork) {}
pub(super) fn service(entry: &ListenerEntry) -> BoxService {
    entry.clone()
}
pub(super) fn handshake(transport: &TcpTransport) -> Arc<qtls::HandshakeSummary> {
    transport.handshake.clone()
}

impl DhttpNetwork {
    pub(crate) async fn listen(
        &'static self,
        name: Arc<str>,
        _scopes: Scopes,
        service: BoxService,
    ) -> Result<()> {
        let port = tcp_mock_port(&name)?;
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(io_error)?;
        let local = mock_authority(&name).await?;
        let handshake = Arc::new(qtls::HandshakeSummary {
            alpn: Some(Bytes::from_static(h3x::ALPN)),
            local: Some(local),
            remote: None,
        });
        {
            let mut listeners = self.listeners.lock().unwrap();
            if listeners.contains_key(&name) {
                return Err(Error::AlreadyListening);
            }
            listeners.insert(name.clone(), service);
        }
        let _cleanup = scopeguard::guard(name.clone(), |name| {
            self.listeners.lock().unwrap().remove(&name);
        });
        eprintln!("h3x/TCP mock {name} on 127.0.0.1:{port}");
        loop {
            let (socket, _) = listener.accept().await.map_err(io_error)?;
            socket.set_nodelay(true).map_err(io_error)?;
            let transport = TcpTransport::new(socket, h3x::Role::Server, handshake.clone());
            let h3 =
                h3x::H3Connection::new(transport, h3x::Settings::default()).map_err(h3_error)?;
            tokio::spawn(serve_connection(self, name.clone(), h3));
        }
    }
}

async fn mock_authority(name: &Arc<str>) -> Result<qtls::LocalAuthority> {
    let identity = crate::home::load_identity(name).await?;
    qtls::LocalAuthority::from_signing_key(
        name.clone(),
        identity.cert_chain().to_vec(),
        identity.signing_key().clone(),
        identity.ocsp().to_vec(),
    )
    .map_err(|error| Error::InvalidRequest {
        message: error.to_string(),
    })
}

fn tcp_mock_port(name: &str) -> Result<u16> {
    std::env::var("DHTTP_TCP_MOCK_PORTS")
        .ok()
        .and_then(|ports| {
            ports
                .split(',')
                .filter_map(|entry| entry.split_once('='))
                .find_map(|(candidate, port)| {
                    (candidate == name)
                        .then(|| port.parse::<u16>().ok())
                        .flatten()
                })
        })
        .ok_or_else(|| Error::InvalidRequest {
            message: format!("no TCP mock port configured for {name}"),
        })
}

pub(super) async fn open_outbound((local_name, remote_name): ConnectionKey) -> Result<H3> {
    let port = tcp_mock_port(&remote_name)?;
    let client_local = mock_authority(&local_name).await?;
    let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(io_error)?;
    socket.set_nodelay(true).map_err(io_error)?;
    let transport = TcpTransport::new(
        socket,
        h3x::Role::Client,
        Arc::new(qtls::HandshakeSummary {
            alpn: Some(Bytes::from_static(h3x::ALPN)),
            local: Some(client_local),
            remote: None,
        }),
    );
    h3x::H3Connection::new(transport, h3x::Settings::default()).map_err(h3_error)
}

pub(super) fn forget_pool_connection(_: &DhttpNetwork, _: &Arc<str>, _: &H3) {}
