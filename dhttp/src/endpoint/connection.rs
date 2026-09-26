async fn quic_endpoint(name: &str) -> Result<qconn::QuicEndpoint> {
    let mut endpoint = qconn::QuicEndpoint::new(crate::home::load_identity(name).await?);
    endpoint.set_alpn(vec![h3x::ALPN.to_vec()]);
    Ok(endpoint)
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
