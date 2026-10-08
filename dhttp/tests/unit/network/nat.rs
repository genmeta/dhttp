use super::super::{InterfaceAddress, test_support::isolated_interfaces};
use super::*;
use futures::FutureExt;

#[tokio::test(start_paused = true)]
async fn initialization_retries_failed_discovery_without_resume() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let Probe::Initial(discovery) = Probe::initial(
        "127.0.0.1:40000".parse().unwrap(),
        async { Err(io::Error::other("discovery unavailable")) },
        {
            let attempts = attempts.clone();
            move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let servers: Arc<[SocketAddr]> =
                    if attempts.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                        // An address-family mismatch also needs another discovery attempt.
                        Arc::from(["[::1]:3478".parse().unwrap()])
                    } else {
                        Arc::from([server])
                    };
                async move { Ok(servers) }
            }
        },
    ) else {
        unreachable!()
    };
    futures::pin_mut!(discovery);
    assert!(futures::poll!(discovery.as_mut()).is_pending());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    tokio::time::advance(STUN_DISCOVERY_RETRY_INTERVAL - Duration::from_millis(1)).await;
    assert!(futures::poll!(discovery.as_mut()).is_pending());
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "discovery must not retry in a busy loop"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(futures::poll!(discovery.as_mut()).is_pending());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    tokio::time::advance(STUN_DISCOVERY_RETRY_INTERVAL).await;
    assert_eq!(discovery.await, vec![server]);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// Drive the binding's probe on this task, just as the interface watcher does.
async fn poll_probe_until(binding: &mut super::super::Binding, ready: impl Fn() -> bool) {
    tokio::time::timeout(
        NAT_PROBE_TIMEOUT * 2,
        std::future::poll_fn(|cx| {
            assert!(
                binding.nat.as_mut().unwrap().poll_unpin(cx).is_pending(),
                "probe ended unexpectedly"
            );
            if ready() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        }),
    )
    .await
    .expect("NAT probe did not reach the expected state");
}

#[tokio::test]
async fn resume_retries_failed_stun_discovery_on_the_same_socket() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let mut binding = state.register(socket.clone()).unwrap().unwrap();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    binding.nat = Some(Nat::new(
        state.dock.clone(),
        state.addresses.clone(),
        socket.clone(),
        bound,
        async { Err(io::Error::other("discovery unavailable before wake")) },
    ));
    let nat = binding.nat.as_mut().unwrap();
    assert!(futures::poll!(&mut *nat).is_pending());
    assert!(matches!(nat.probe, Probe::Initial(_)));
    nat.resume(async move { Ok(Arc::from([server_addr])) });
    let mut packet = [0; 4096];
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = nat => panic!("maintenance ended"),
            result = server.recv_from(&mut packet) => { result.unwrap(); },
        }
    })
    .await
    .expect("resume must retry discovery and send STUN immediately");
    assert!(Arc::ptr_eq(
        &socket,
        &state.dock.find_socket(bound).unwrap()
    ));
    state.remove(&binding);
}

#[tokio::test]
async fn nat_classifies_once_then_heartbeats_replace_and_withdraw_mappings() {
    use qbase::{
        datagram::{Datagram, WriteDatagram, be_datagram},
        net::route::Link,
    };
    use qprotocol::protocol::stun::{Attr, Message, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let mut binding = state.register(socket.clone()).unwrap().unwrap();
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let changes = Arc::new(AtomicUsize::new(0));
    let heartbeats = Arc::new(AtomicUsize::new(0));
    let (unanswered, mut awaiting_unanswered) = tokio::sync::oneshot::channel();
    let stun = state.dock.topology().stun().clone();
    let responder = tokio::spawn({
        let changes = changes.clone();
        let heartbeats = heartbeats.clone();
        let socket = socket.clone();
        async move {
            let mut unanswered = Some(unanswered);
            let mut count = 0;
            let mut packet = vec![0; 4096];
            loop {
                let (len, peer) = listener.recv_from(&mut packet).await.unwrap();
                let Datagram::Stun(id, Message::Request(request)) =
                    be_datagram(bytes::BytesMut::from(&packet[..len])).unwrap()
                else {
                    panic!("expected STUN request")
                };
                count += 1;
                let changed = SocketAddr::new("127.0.0.2".parse().unwrap(), server.port() ^ 1);
                let source = match request.change_request() {
                    Some(flags) if flags & qbase::datagram::stun::CHANGE_IP != 0 => {
                        changes.fetch_add(1, Ordering::SeqCst);
                        changed
                    }
                    Some(_) => {
                        changes.fetch_add(1, Ordering::SeqCst);
                        SocketAddr::new(server.ip(), changed.port())
                    }
                    None => server,
                };
                let mapped = if count <= 3 {
                    bound
                } else {
                    let heartbeat = heartbeats.fetch_add(1, Ordering::SeqCst);
                    if heartbeat == 1 {
                        // Leave a refresh in flight; a second resume must cancel it
                        // instead of waiting for its ten-second measurement timeout.
                        let _ = unanswered.take().unwrap().send(());
                        continue;
                    }
                    if heartbeat == 0 {
                        "8.8.8.8:41000"
                    } else {
                        "8.8.8.8:42000"
                    }
                    .parse()
                    .unwrap()
                };
                let response = Response::with(vec![
                    Attr::MappedAddress(mapped),
                    Attr::ChangedAddress(changed),
                    Attr::SourceAddress(source),
                ]);
                // Inject changed-source responses without configuring extra loopback IPs.
                if source != server {
                    stun.on_datagram(
                        &socket,
                        id,
                        Message::Response(response),
                        Link::new(bound, source),
                    )
                    .await
                    .unwrap();
                } else {
                    let mut response_packet = bytes::BytesMut::new();
                    response_packet
                        .put_datagram(&Datagram::Stun(id, Message::Response(response)))
                        .unwrap();
                    listener.send_to(&response_packet, peer).await.unwrap();
                }
            }
        }
    });
    binding.nat = Some(Nat::new(
        state.dock.clone(),
        state.addresses.clone(),
        socket.clone(),
        bound,
        async move { Ok(Arc::from([server])) },
    ));
    let first = "8.8.8.8:41000".parse().unwrap();
    let initial = EndpointAddr::direct(first);
    let initial_endpoints = [initial, EndpointAddr::mediate(server, first)];
    poll_probe_until(&mut binding, || {
        state.addresses.ddns_endpoints().as_ref() == initial_endpoints
    })
    .await;
    assert_eq!(state.addresses.nat(bound), Some(NatType::FullCone));
    assert!(matches!(
        &binding.nat.as_ref().unwrap().probe,
        Probe::Heartbeat {
            nat_type: Some(NatType::FullCone),
            ..
        }
    ));
    assert_eq!(changes.load(Ordering::SeqCst), 2);
    assert_eq!(heartbeats.load(Ordering::SeqCst), 1);
    let mut ddns = state.addresses.subscribe_ddns();
    assert_eq!(ddns.borrow_and_update().as_ref(), &initial_endpoints);
    assert!(
        state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::mediate(server, first))
            .is_some()
    );
    binding.nat.as_mut().unwrap().resume(std::future::pending());
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = binding.nat.as_mut().unwrap() => panic!("probe ended unexpectedly"),
            _ = &mut awaiting_unanswered => {},
        }
    })
    .await
    .expect("resume must start a heartbeat without waiting twenty seconds");
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &initial_endpoints
    );
    binding.nat.as_mut().unwrap().resume(std::future::pending());
    let second = "8.8.8.8:42000".parse().unwrap();
    let refreshed_endpoints = [
        EndpointAddr::direct(second),
        EndpointAddr::mediate(server, second),
    ];
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_probe_until(&mut binding, || {
            state.addresses.ddns_endpoints().as_ref() == refreshed_endpoints
        }),
    )
    .await
    .expect("resume must cancel the unanswered heartbeat and immediately refresh");
    assert_eq!(state.addresses.nat(bound), Some(NatType::FullCone));
    assert_eq!(
        changes.load(Ordering::SeqCst),
        2,
        "heartbeat must not rerun NAT classification"
    );
    assert_eq!(heartbeats.load(Ordering::SeqCst), 3);
    assert_eq!(ddns.borrow_and_update().as_ref(), &refreshed_endpoints);
    assert!(state.dock.topology().quic().find_socket(initial).is_none());
    assert!(
        state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::mediate(server, first))
            .is_none()
    );
    // A heartbeat timeout withdraws its public mapping but keeps the direct socket.
    responder.abort();
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL).await;
    poll_probe_until(&mut binding, || state.addresses.ddns_endpoints().is_empty()).await;
    assert!(state.addresses.ddns_endpoints().is_empty());
    assert!(
        state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(bound))
            .is_some()
    );
    state.bindings.insert(
        InterfaceAddress {
            name: "test".into(),
            index: 1,
            hw_addr: String::new(),
            addr: bound,
        },
        binding,
    );
    state.snapshot.clear();
    state.scan();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL * 3).await;
    assert!(state.addresses.ddns_endpoints().is_empty());
    assert_eq!(state.addresses.nat(bound), None);
    assert!(state.dock.find_socket(bound).is_none());
}

#[tokio::test]
async fn nat_endpoint_conflict_preserves_previous_mapping_and_foreign_socket() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = state.register(socket.clone()).unwrap().unwrap();
    let relay = "8.8.4.4:20002".parse().unwrap();
    let first = "8.8.8.8:41000".parse().unwrap();
    let second = "8.8.8.8:42000".parse().unwrap();
    let mappings = HashMap::from([(relay, first)]);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        state.addresses.nat(binding.bound),
        &HashMap::new(),
        &mappings,
    )
    .unwrap();
    let foreign = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    state.dock.add(foreign.clone()).unwrap().unwrap();
    state
        .dock
        .topology()
        .quic()
        .register(EndpointAddr::direct(second), &foreign)
        .unwrap();
    assert!(
        apply_outer_mappings(
            &state.dock,
            &state.addresses,
            &socket,
            state.addresses.nat(binding.bound),
            &mappings,
            &HashMap::from([(relay, second)])
        )
        .is_err()
    );
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(relay, first)]
    );
    assert!(Arc::ptr_eq(
        &socket,
        &state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::mediate(relay, first))
            .unwrap()
    ));
    assert!(Arc::ptr_eq(
        &foreign,
        &state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(second))
            .unwrap()
    ));
    state.remove(&binding);
}

#[tokio::test]
async fn nat_publication_conflict_restores_registrations_and_preserves_existing_records() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = state.register(socket.clone()).unwrap().unwrap();
    state.addresses.set_nat(binding.bound, NatType::FullCone);
    let agent = "8.8.4.4:20002".parse().unwrap();
    let first = "8.8.8.8:41000".parse().unwrap();
    let second = "8.8.8.8:42000".parse().unwrap();
    let previous = HashMap::from([(agent, first)]);
    let refreshed = HashMap::from([(agent, second)]);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        state.addresses.nat(binding.bound),
        &HashMap::new(),
        &previous,
    )
    .unwrap();

    // A publication can conflict even after every QUIC registration succeeds.
    let foreign = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let conflict = EndpointAddr::mediate(agent, second);
    state.addresses.insert_outer(&foreign, conflict).unwrap();
    let published = state.addresses.ddns_endpoints();
    assert!(
        apply_outer_mappings(
            &state.dock,
            &state.addresses,
            &socket,
            state.addresses.nat(binding.bound),
            &previous,
            &refreshed,
        )
        .is_err()
    );
    assert_eq!(state.addresses.ddns_endpoints(), published);
    let quic = state.dock.topology().quic();
    for endpoint in [
        EndpointAddr::direct(binding.bound),
        EndpointAddr::direct(first),
        EndpointAddr::mediate(agent, first),
    ] {
        assert!(Arc::ptr_eq(&socket, &quic.find_socket(endpoint).unwrap()));
    }
    assert!(quic.find_socket(EndpointAddr::direct(second)).is_none());
    assert!(quic.find_socket(conflict).is_none());

    // The caller retains the previous mappings and can retry after the conflict clears.
    state.addresses.remove(conflict);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        state.addresses.nat(binding.bound),
        &previous,
        &refreshed,
    )
    .unwrap();
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::direct(second), conflict]
    );
    assert!(quic.find_socket(EndpointAddr::direct(first)).is_none());
    assert!(Arc::ptr_eq(&socket, &quic.find_socket(conflict).unwrap()));
    state.remove(&binding);
    state.addresses.remove_bound(foreign.local_addr().unwrap());
}

#[tokio::test]
async fn full_cone_shared_mapping_keeps_direct_and_remaining_relay_when_one_agent_fails() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = state.register(socket.clone()).unwrap().unwrap();
    let outer = "8.8.8.8:41000".parse().unwrap();
    let agents = [
        "1.1.1.1:20002".parse().unwrap(),
        "8.8.4.4:20002".parse().unwrap(),
    ];
    let previous = HashMap::from([(agents[0], outer), (agents[1], outer)]);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        Some(NatType::FullCone),
        &HashMap::new(),
        &previous,
    )
    .unwrap();
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[
            EndpointAddr::direct(outer),
            EndpointAddr::mediate(agents[0], outer),
            EndpointAddr::mediate(agents[1], outer),
        ]
    );
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        Some(NatType::FullCone),
        &previous,
        &HashMap::from([(agents[1], outer)]),
    )
    .unwrap();
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[
            EndpointAddr::direct(outer),
            EndpointAddr::mediate(agents[1], outer),
        ]
    );
    let quic = state.dock.topology().quic();
    assert!(quic.find_socket(EndpointAddr::direct(outer)).is_some());
    assert!(
        quic.find_socket(EndpointAddr::mediate(agents[0], outer))
            .is_none()
    );
    state.remove(&binding);
}

#[tokio::test]
async fn classification_failure_does_not_stop_binding_heartbeats_or_invent_nat_type() {
    use qbase::datagram::{Datagram, WriteDatagram, be_datagram};
    use qprotocol::protocol::stun::{Attr, Message, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let mut binding = state.register(socket.clone()).unwrap().unwrap();
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let responder = tokio::spawn({
        let calls = calls.clone();
        async move {
            let mut packet = vec![0; 4096];
            loop {
                let (len, peer) = listener.recv_from(&mut packet).await.unwrap();
                let Datagram::Stun(id, Message::Request(request)) =
                    be_datagram(bytes::BytesMut::from(&packet[..len])).unwrap()
                else {
                    panic!("expected STUN request")
                };
                assert!(request.change_request().is_none());
                calls.fetch_add(1, Ordering::SeqCst);
                // No CHANGED-ADDRESS: classification fails, binding heartbeats still work.
                let response =
                    Response::with(vec![Attr::MappedAddress("8.8.8.8:41000".parse().unwrap())]);
                let mut response_packet = bytes::BytesMut::new();
                response_packet
                    .put_datagram(&Datagram::Stun(id, Message::Response(response)))
                    .unwrap();
                listener.send_to(&response_packet, peer).await.unwrap();
            }
        }
    });
    binding.nat = Some(Nat::new(
        state.dock.clone(),
        state.addresses.clone(),
        socket,
        bound,
        async move { Ok(Arc::from([server])) },
    ));
    poll_probe_until(&mut binding, || {
        !state.addresses.ddns_endpoints().is_empty()
    })
    .await;
    assert!(matches!(
        &binding.nat.as_ref().unwrap().probe,
        Probe::Heartbeat { nat_type: None, .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.addresses.nat(bound), None);
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(
            server,
            "8.8.8.8:41000".parse().unwrap()
        )]
    );
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL).await;
    tokio::time::resume();
    poll_probe_until(&mut binding, || calls.load(Ordering::SeqCst) == 3).await;
    assert_eq!(state.addresses.nat(bound), None);
    state.bindings.insert(
        InterfaceAddress {
            name: "test".into(),
            index: 1,
            hw_addr: String::new(),
            addr: bound,
        },
        binding,
    );
    state.snapshot.clear();
    state.scan();
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL * 3).await;
    tokio::task::yield_now().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "removed bindings must stop heartbeats"
    );
    assert!(state.addresses.ddns_endpoints().is_empty());
    responder.abort();
}

#[tokio::test]
async fn filtering_nat_publishes_relay_records_and_keeps_direct_punch_endpoints() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = state.register(socket.clone()).unwrap().unwrap();
    state
        .addresses
        .set_nat(binding.bound, NatType::RestrictedPort);
    let first = "8.8.8.8:41000".parse().unwrap();
    let changed = "8.8.8.8:42000".parse().unwrap();
    let agents = [
        "8.8.4.4:20002".parse().unwrap(),
        "1.1.1.1:20002".parse().unwrap(),
    ];
    let previous = HashMap::from([(agents[0], first), (agents[1], first)]);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        state.addresses.nat(binding.bound),
        &HashMap::new(),
        &previous,
    )
    .unwrap();
    let mut expected = agents
        .map(|agent| EndpointAddr::mediate(agent, first))
        .to_vec();
    expected.sort_unstable();
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        expected.as_slice()
    );
    assert!(
        state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(first))
            .is_some()
    );
    let refreshed = HashMap::from([(agents[0], changed)]);
    apply_outer_mappings(
        &state.dock,
        &state.addresses,
        &socket,
        state.addresses.nat(binding.bound),
        &previous,
        &refreshed,
    )
    .unwrap();
    assert_eq!(
        state.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(agents[0], changed)]
    );
    for endpoint in expected {
        assert!(state.dock.topology().quic().find_socket(endpoint).is_none());
    }
    assert!(
        state
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(first))
            .is_none()
    );
    state.remove(&binding);
}
