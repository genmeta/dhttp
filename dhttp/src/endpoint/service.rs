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
