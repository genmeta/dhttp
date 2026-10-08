use super::super::{InterfaceAddress, test_support::isolated_bindings};
use super::*;
use futures::FutureExt;

// Drive the binding's probe on this task, just as the interface watcher does.
async fn poll_probe_until(binding: &mut super::super::Binding, ready: impl Fn() -> bool) {
    tokio::time::timeout(
        NAT_PROBE_TIMEOUT * 2,
        std::future::poll_fn(|cx| {
            assert!(
                binding.nat_probe.poll_unpin(cx).is_pending(),
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
async fn nat_classifies_once_then_heartbeats_replace_and_withdraw_mappings() {
    use qbase::{
        datagram::{Datagram, WriteDatagram, be_datagram},
        net::route::Link,
    };
    use qprotocol::protocol::stun::{Attr, Message, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let mut binding = bindings.register(socket.clone()).unwrap().unwrap();
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let changes = Arc::new(AtomicUsize::new(0));
    let heartbeats = Arc::new(AtomicUsize::new(0));
    let stun = bindings.dock.topology().stun().clone();
    let responder = tokio::spawn({
        let changes = changes.clone();
        let heartbeats = heartbeats.clone();
        let socket = socket.clone();
        async move {
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
    binding.nat_probe = probe_nat(
        bindings.dock.clone(),
        bindings.addresses.clone(),
        socket.clone(),
        async move { Ok(Arc::from([server])) },
    )
    .boxed();
    let first = "8.8.8.8:41000".parse().unwrap();
    let initial = EndpointAddr::direct(first);
    poll_probe_until(&mut binding, || {
        bindings.addresses.ddns_endpoints().as_ref() == [initial]
    })
    .await;
    assert_eq!(bindings.addresses.nat(bound), Some(NatType::FullCone));
    assert_eq!(changes.load(Ordering::SeqCst), 2);
    assert_eq!(heartbeats.load(Ordering::SeqCst), 1);
    let mut ddns = bindings.addresses.subscribe_ddns();
    assert_eq!(ddns.borrow_and_update().as_ref(), &[initial]);
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::mediate(server, first))
            .is_some()
    );
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL).await;
    tokio::time::resume();
    let second = "8.8.8.8:42000".parse().unwrap();
    poll_probe_until(&mut binding, || {
        bindings.addresses.ddns_endpoints().as_ref() == [EndpointAddr::direct(second)]
    })
    .await;
    assert_eq!(bindings.addresses.nat(bound), Some(NatType::FullCone));
    assert_eq!(
        changes.load(Ordering::SeqCst),
        2,
        "heartbeat must not rerun NAT classification"
    );
    assert_eq!(heartbeats.load(Ordering::SeqCst), 2);
    assert_eq!(
        ddns.borrow_and_update().as_ref(),
        &[EndpointAddr::direct(second)]
    );
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(initial)
            .is_none()
    );
    assert!(
        bindings
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
    poll_probe_until(&mut binding, || {
        bindings.addresses.ddns_endpoints().is_empty()
    })
    .await;
    assert!(bindings.addresses.ddns_endpoints().is_empty());
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(bound))
            .is_some()
    );
    bindings.bindings.insert(
        InterfaceAddress {
            name: "test".into(),
            index: 1,
            hw_addr: String::new(),
            addr: bound,
        },
        binding,
    );
    bindings.scan(&HashMap::new());
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL * 3).await;
    assert!(bindings.addresses.ddns_endpoints().is_empty());
    assert_eq!(bindings.addresses.nat(bound), None);
    assert!(bindings.dock.find_socket(bound).is_none());
}

#[tokio::test]
async fn nat_endpoint_conflict_preserves_previous_mapping_and_foreign_socket() {
    let bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = bindings.register(socket.clone()).unwrap().unwrap();
    let relay = "8.8.4.4:20002".parse().unwrap();
    let first = "8.8.8.8:41000".parse().unwrap();
    let second = "8.8.8.8:42000".parse().unwrap();
    let mappings = HashMap::from([(relay, first)]);
    apply_nat_mappings(
        &bindings.dock,
        &bindings.addresses,
        &socket,
        &HashMap::new(),
        &mappings,
    )
    .unwrap();
    let foreign = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    bindings.dock.add(foreign.clone()).unwrap().unwrap();
    bindings
        .dock
        .topology()
        .quic()
        .register(EndpointAddr::direct(second), &foreign)
        .unwrap();
    assert!(
        apply_nat_mappings(
            &bindings.dock,
            &bindings.addresses,
            &socket,
            &mappings,
            &HashMap::from([(relay, second)])
        )
        .is_err()
    );
    assert_eq!(
        bindings.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(relay, first)]
    );
    assert!(Arc::ptr_eq(
        &socket,
        &bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::mediate(relay, first))
            .unwrap()
    ));
    assert!(Arc::ptr_eq(
        &foreign,
        &bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(second))
            .unwrap()
    ));
    bindings.withdraw(&binding);
}

#[tokio::test]
async fn nat_publication_conflict_restores_registrations_and_preserves_existing_records() {
    let bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = bindings.register(socket.clone()).unwrap().unwrap();
    let agent = "8.8.4.4:20002".parse().unwrap();
    let first = "8.8.8.8:41000".parse().unwrap();
    let second = "8.8.8.8:42000".parse().unwrap();
    let previous = HashMap::from([(agent, first)]);
    let refreshed = HashMap::from([(agent, second)]);
    apply_nat_mappings(
        &bindings.dock,
        &bindings.addresses,
        &socket,
        &HashMap::new(),
        &previous,
    )
    .unwrap();

    // A publication can conflict even after every QUIC registration succeeds.
    let foreign = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let conflict = EndpointAddr::mediate(agent, second);
    bindings.addresses.insert_outer(&foreign, conflict).unwrap();
    let published = bindings.addresses.ddns_endpoints();
    assert!(
        apply_nat_mappings(
            &bindings.dock,
            &bindings.addresses,
            &socket,
            &previous,
            &refreshed,
        )
        .is_err()
    );
    assert_eq!(bindings.addresses.ddns_endpoints(), published);
    let quic = bindings.dock.topology().quic();
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
    bindings.addresses.remove(conflict);
    apply_nat_mappings(
        &bindings.dock,
        &bindings.addresses,
        &socket,
        &previous,
        &refreshed,
    )
    .unwrap();
    assert_eq!(bindings.addresses.ddns_endpoints().as_ref(), &[conflict]);
    assert!(quic.find_socket(EndpointAddr::direct(first)).is_none());
    assert!(Arc::ptr_eq(&socket, &quic.find_socket(conflict).unwrap()));
    bindings.withdraw(&binding);
    bindings
        .addresses
        .remove_bound(foreign.local_addr().unwrap());
}

#[tokio::test]
async fn classification_failure_does_not_stop_binding_heartbeats_or_invent_nat_type() {
    use qbase::datagram::{Datagram, WriteDatagram, be_datagram};
    use qprotocol::protocol::stun::{Attr, Message, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let mut binding = bindings.register(socket.clone()).unwrap().unwrap();
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
    binding.nat_probe = probe_nat(
        bindings.dock.clone(),
        bindings.addresses.clone(),
        socket,
        async move { Ok(Arc::from([server])) },
    )
    .boxed();
    poll_probe_until(&mut binding, || {
        !bindings.addresses.ddns_endpoints().is_empty()
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(bindings.addresses.nat(bound), None);
    assert_eq!(
        bindings.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(
            server,
            "8.8.8.8:41000".parse().unwrap()
        )]
    );
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL).await;
    tokio::time::resume();
    poll_probe_until(&mut binding, || calls.load(Ordering::SeqCst) == 3).await;
    assert_eq!(bindings.addresses.nat(bound), None);
    bindings.bindings.insert(
        InterfaceAddress {
            name: "test".into(),
            index: 1,
            hw_addr: String::new(),
            addr: bound,
        },
        binding,
    );
    bindings.scan(&HashMap::new());
    tokio::time::pause();
    tokio::time::advance(NAT_HEARTBEAT_INTERVAL * 3).await;
    tokio::task::yield_now().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "removed bindings must stop heartbeats"
    );
    assert!(bindings.addresses.ddns_endpoints().is_empty());
    responder.abort();
}

#[tokio::test]
async fn filtering_nat_publishes_relay_records_and_keeps_direct_punch_endpoints() {
    let bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let binding = bindings.register(socket.clone()).unwrap().unwrap();
    bindings
        .addresses
        .set_nat(binding.bound, NatType::RestrictedPort);
    let first = "8.8.8.8:41000".parse().unwrap();
    let changed = "8.8.8.8:42000".parse().unwrap();
    let agents = [
        "8.8.4.4:20002".parse().unwrap(),
        "1.1.1.1:20002".parse().unwrap(),
    ];
    let previous = HashMap::from([(agents[0], first), (agents[1], first)]);
    apply_nat_mappings(
        &bindings.dock,
        &bindings.addresses,
        &socket,
        &HashMap::new(),
        &previous,
    )
    .unwrap();
    let mut expected = agents
        .map(|agent| EndpointAddr::mediate(agent, first))
        .to_vec();
    expected.sort_unstable();
    assert_eq!(
        bindings.addresses.ddns_endpoints().as_ref(),
        expected.as_slice()
    );
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(first))
            .is_some()
    );
    let refreshed = HashMap::from([(agents[0], changed)]);
    apply_nat_mappings(
        &bindings.dock,
        &bindings.addresses,
        &socket,
        &previous,
        &refreshed,
    )
    .unwrap();
    assert_eq!(
        bindings.addresses.ddns_endpoints().as_ref(),
        &[EndpointAddr::mediate(agents[0], changed)]
    );
    for endpoint in expected {
        assert!(
            bindings
                .dock
                .topology()
                .quic()
                .find_socket(endpoint)
                .is_none()
        );
    }
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(EndpointAddr::direct(first))
            .is_none()
    );
    bindings.withdraw(&binding);
}
