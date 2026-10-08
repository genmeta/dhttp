use super::test_support::isolated_interfaces;
use super::*;
use qconn::Scopes;

#[test]
fn interface_snapshot_filters_unusable_ips_and_preserves_ipv6_scope() {
    let snapshot = HashMap::from([
        (
            7,
            netwatcher::Interface {
                index: 7,
                name: "test7".into(),
                hw_addr: String::new(),
                ips: [
                    "0.0.0.0",
                    "::",
                    "224.0.0.1",
                    "ff02::1",
                    "127.0.0.1",
                    "192.168.1.2",
                    "169.254.1.2",
                    "fe80::1234",
                    "2001:db8::1",
                    "::1",
                ]
                .map(|ip| netwatcher::IpRecord {
                    ip: ip.parse().unwrap(),
                    prefix_len: 0,
                })
                .into(),
            },
        ),
        (
            0,
            netwatcher::Interface {
                index: 0,
                name: "invalid".into(),
                hw_addr: String::new(),
                ips: vec![netwatcher::IpRecord {
                    ip: "10.0.0.1".parse().unwrap(),
                    prefix_len: 8,
                }],
            },
        ),
    ]);
    let current = interfaces(&snapshot);
    let addresses: std::collections::HashSet<_> = current.keys().map(|key| key.addr).collect();
    assert_eq!(
        addresses,
        [
            "127.0.0.1:0",
            "192.168.1.2:0",
            "169.254.1.2:0",
            "[fe80::1234%7]:0",
            "[2001:db8::1]:0",
            "[::1]:0"
        ]
        .map(|addr| addr.parse::<SocketAddr>().unwrap())
        .into()
    );
    assert!(
        current
            .iter()
            .all(|(_, device)| device.name() == "test7" && device.index().get() == 7)
    );
}

fn loopback_interface() -> netwatcher::Interface {
    let mut loopback = netwatcher::list_interfaces()
        .unwrap()
        .into_values()
        .find(|interface| {
            interface
                .ips
                .iter()
                .any(|record| record.ip == std::net::Ipv4Addr::LOCALHOST)
        })
        .expect("an IPv4 loopback interface");
    loopback
        .ips
        .retain(|record| record.ip == std::net::Ipv4Addr::LOCALHOST);
    loopback
}

#[tokio::test]
async fn scan_preserves_ports_and_foreign_sockets_and_withdraws_all_endpoints() {
    let mut state = isolated_interfaces().await;
    let dock = state.dock.clone();
    let addresses = state.addresses.clone();
    let loopback = loopback_interface();
    let device = BoundDevice::new(loopback.name.clone(), loopback.index).unwrap();
    let snapshot = HashMap::from([(loopback.index, loopback)]);
    // Both unscoped temporary sockets and another owner's device-bound socket survive.
    let foreign = [
        Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()),
        Arc::new(UdpSocket::bind_to_device("127.0.0.1:0".parse().unwrap(), device).unwrap()),
    ];
    for socket in &foreign {
        dock.add(socket.clone()).unwrap().unwrap();
    }
    state.snapshot.clear();
    state.scan();
    assert_eq!(dock.len(), 2);
    state.snapshot = snapshot.clone();
    state.scan();
    assert_eq!(state.bindings.len(), 1);
    let first = state.bindings.values().next().unwrap().socket.clone();
    let bound = first.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    let mut events = addresses.subscribe_punch(Scopes::ALL);
    assert!(
        matches!(events.try_recv().unwrap(), qprotocol::AddressEvent::Added { endpoint, .. } if endpoint == direct)
    );
    state.scan();
    assert!(Arc::ptr_eq(&first, &dock.find_socket(bound).unwrap()));
    assert_eq!(state.bindings.values().next().unwrap().bound, bound);
    assert!(
        events.try_recv().is_err(),
        "unchanged bindings must not be republished"
    );

    let outer = EndpointAddr::direct("8.8.8.8:4567".parse().unwrap());
    let relay = EndpointAddr::mediate("8.8.4.4:3478".parse().unwrap(), outer.addr());
    for endpoint in [outer, relay] {
        dock.topology().quic().register(endpoint, &first).unwrap();
    }
    addresses.insert_outer(&first, outer).unwrap();
    addresses.set_nat(bound, qbase::net::NatType::RestrictedCone);
    state.snapshot.clear();
    state.scan();
    assert!(dock.find_socket(bound).is_none());
    assert!(addresses.mdns_endpoints(bound).is_empty());
    assert!(addresses.ddns_endpoints().is_empty());
    assert_eq!(addresses.nat(bound), None);
    for endpoint in [direct, outer, relay] {
        assert!(dock.topology().quic().find_socket(endpoint).is_none());
    }
    let mut removed = false;
    while let Ok(event) = events.try_recv() {
        removed |= matches!(event, qprotocol::AddressEvent::BoundRemoved { bound: candidate } if candidate == bound);
    }
    assert!(removed);
    state.snapshot = snapshot.clone();
    state.scan();
    assert_eq!(state.bindings.len(), 1);
    let replacement = state.bindings.values().next().unwrap().bound;
    assert_ne!(bound, replacement);
    drop(state);
    assert!(addresses.mdns_endpoints(replacement).is_empty());
    assert!(dock.find_socket(replacement).is_none());
    for socket in &foreign {
        assert!(Arc::ptr_eq(
            socket,
            &dock.find_socket(socket.local_addr().unwrap()).unwrap()
        ));
    }
}

#[tokio::test]
async fn scan_rebinds_when_interface_identity_changes() {
    let mut state = isolated_interfaces().await;
    let loopback = loopback_interface();
    let snapshot = HashMap::from([(loopback.index, loopback.clone())]);
    state.snapshot = snapshot.clone();
    state.scan();
    let original = state.bindings.values().next().unwrap().socket.clone();
    let bound = original.local_addr().unwrap();
    // A new device may reuse both index and name; hardware identity still changes.
    let mut changed = loopback.clone();
    changed.hw_addr.push_str("-replaced");
    state.snapshot = HashMap::from([(changed.index, changed)]);
    state.scan();
    assert_eq!(state.bindings.len(), 1);
    assert!(state.dock.find_socket(bound).is_none());
    assert!(state.addresses.mdns_endpoints(bound).is_empty());
    let replacement = state.bindings.values().next().unwrap().socket.clone();
    assert!(!Arc::ptr_eq(&original, &replacement));

    let mut changed = loopback;
    changed.index = u32::MAX;
    state.snapshot = HashMap::from([(changed.index, changed)]);
    state.scan();
    assert!(state.bindings.is_empty(), "invalid interface cannot bind");
    assert!(
        state
            .addresses
            .mdns_endpoints(replacement.local_addr().unwrap())
            .is_empty()
    );
    state.snapshot = snapshot.clone();
    state.scan();
    assert_eq!(state.bindings.len(), 1);
}

#[tokio::test]
async fn registration_preserves_existing_owners_and_rolls_back_failed_publication() {
    let state = isolated_interfaces().await;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    state.dock.add(socket.clone()).unwrap().unwrap();
    assert!(state.register(socket.clone()).unwrap().is_none());
    assert!(state.addresses.mdns_endpoints(bound).is_empty());
    assert!(state.dock.find_socket(bound).is_some());
    state.dock.remove(&socket);
    state.addresses.insert_inner(&socket, direct).unwrap();
    assert!(state.register(socket.clone()).is_err());
    assert!(state.dock.find_socket(bound).is_none());
    assert!(state.dock.topology().quic().find_socket(direct).is_none());
    assert_eq!(state.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    state.addresses.remove_bound(bound);
    let registration = state.register(socket).unwrap().unwrap();
    assert_eq!(state.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    state.remove(&registration);
}

#[tokio::test]
async fn scan_withdraws_and_rebinds_after_receiver_exit_or_abort() {
    use qbase::{datagram::forward::Payload, net::route::Pathway};
    for abort in [false, true] {
        let mut state = isolated_interfaces().await;
        let loopback = loopback_interface();
        let snapshot = HashMap::from([(loopback.index, loopback)]);
        state.snapshot = snapshot.clone();
        state.scan();
        let binding = state.bindings.values().next().unwrap();
        let socket = binding.socket.clone();
        let bound = binding.bound;
        let receiver = binding.receiver.clone();
        if abort {
            receiver.abort();
        } else {
            // Force a real receive-loop error by forwarding IPv6 through IPv4.
            state.dock.topology().forward().serve(bound, &socket);
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let pathway = Pathway::new(
                EndpointAddr::direct("[::1]:12345".parse().unwrap()),
                EndpointAddr::direct("[::1]:9".parse().unwrap()),
            );
            let offset = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
            let mut bytes = bytes::BytesMut::zeroed(offset + 1);
            bytes[offset] = 0x40;
            let packet = Payload::from_raw(&pathway, bytes, offset).unwrap();
            peer.send_to(packet.as_ref(), bound).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while !receiver.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !state.addresses.mdns_endpoints(bound).is_empty(),
            "Dock leaves publication to Network"
        );
        state.snapshot = snapshot.clone();
        state.scan();
        assert!(state.addresses.mdns_endpoints(bound).is_empty());
        assert!(state.dock.find_socket(bound).is_none());
        assert_eq!(state.bindings.len(), 1);
        assert_ne!(state.bindings.values().next().unwrap().bound, bound);
    }
}

#[tokio::test]
async fn resume_uses_fresh_interfaces_and_repairs_bindings_before_returning() {
    let state = isolated_interfaces().await;
    let dock = state.dock.clone();
    let addresses = state.addresses.clone();
    // Simulate an empty cached snapshot after missing the interface's return.
    let (interfaces, task) = Interfaces::start(state);
    let task = scopeguard::guard(task, |task| task.abort());
    tokio::time::timeout(Duration::from_secs(2), async {
        let (first, second) = tokio::join!(interfaces.resume(), interfaces.resume());
        first.unwrap();
        second.unwrap();
    })
    .await
    .expect("resume must scan without waiting for another OS event or task poll");
    let mut events = addresses.subscribe_punch(Scopes::ALL);
    let mut found_loopback = false;
    while let Ok(qprotocol::AddressEvent::Added {
        bound, endpoint, ..
    }) = events.try_recv()
    {
        if endpoint.addr().ip() == std::net::Ipv4Addr::LOCALHOST {
            found_loopback = true;
            assert!(dock.find_socket(bound).is_some());
        }
    }
    assert!(
        found_loopback,
        "resume must return with fresh loopback bindings"
    );
    let task = scopeguard::ScopeGuard::into_inner(task);
    task.abort();
    let _ = task.await;
    assert!(dock.is_empty());
    assert!(addresses.ddns_endpoints().is_empty());
}

#[tokio::test]
async fn resume_reports_a_stopped_maintenance_task() {
    for before_first_poll in [true, false] {
        let mut state = isolated_interfaces().await;
        state.snapshot = netwatcher::list_interfaces().unwrap();
        state.scan();
        let dock = state.dock.clone();
        let addresses = state.addresses.clone();
        let (interfaces, task) = Interfaces::start(state);
        if !before_first_poll {
            tokio::task::yield_now().await;
            assert!(
                interfaces
                    .state
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .waker
                    .is_some()
            );
        }
        task.abort();
        let _ = task.await;
        assert!(dock.is_empty());
        assert!(addresses.ddns_endpoints().is_empty());
        let network = crate::DhttpNetwork {
            interfaces,
            listeners: Default::default(),
            pool: h3x::Pool::new(super::super::connection::connect),
        };
        let crate::Error::Io { source } = network.resume().await.unwrap_err() else {
            panic!("expected a maintenance I/O error");
        };
        assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    }
}

#[tokio::test(start_paused = true)]
async fn interfaces_keep_checking_bindings_after_resume_and_multiple_ticks() {
    let loopback = loopback_interface();
    let snapshot = HashMap::from([(loopback.index, loopback)]);
    let mut state = isolated_interfaces().await;
    state.snapshot = snapshot.clone();
    state.scan();
    let dock = state.dock.clone();
    let addresses = state.addresses.clone();
    let (interfaces, task) = Interfaces::start(state);
    let task = scopeguard::guard(task, |task| task.abort());
    tokio::task::yield_now().await;
    interfaces.resume().await.unwrap();
    tokio::task::yield_now().await;
    for _ in 0..3 {
        let socket = {
            let state = interfaces.state.lock().unwrap();
            state
                .as_ref()
                .unwrap()
                .bindings
                .values()
                .find(|binding| binding.bound.ip() == std::net::Ipv4Addr::LOCALHOST)
                .unwrap()
                .socket
                .clone()
        };
        let bound = socket.local_addr().unwrap();
        assert!(dock.remove(&socket));
        tokio::time::advance(BINDING_CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(addresses.mdns_endpoints(bound).is_empty());
        assert!(dock.find_socket(bound).is_none());
        assert!(
            interfaces
                .state
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .bindings
                .values()
                .any(|binding| binding.bound.ip() == bound.ip() && binding.bound != bound)
        );
    }
    let task = scopeguard::ScopeGuard::into_inner(task);
    task.abort();
    let _ = task.await;
    assert!(dock.is_empty());
}
