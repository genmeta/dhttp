use super::test_support::isolated_bindings;
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
    let mut bindings = isolated_bindings();
    let dock = bindings.dock.clone();
    let addresses = bindings.addresses.clone();
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
    bindings.scan(&HashMap::new());
    assert_eq!(dock.len(), 2);
    bindings.scan(&snapshot);
    assert_eq!(bindings.bindings.len(), 1);
    let first = bindings.bindings.values().next().unwrap().socket.clone();
    let bound = first.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    assert_eq!(addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    let mut events = addresses.subscribe_punch(Scopes::ALL);
    assert!(
        matches!(events.try_recv().unwrap(), qprotocol::AddressEvent::Added { endpoint, .. } if endpoint == direct)
    );
    bindings.scan(&snapshot);
    assert!(Arc::ptr_eq(&first, &dock.find_socket(bound).unwrap()));
    assert_eq!(bindings.bindings.values().next().unwrap().bound, bound);
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
    bindings.scan(&HashMap::new());
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
    bindings.scan(&snapshot);
    assert_eq!(bindings.bindings.len(), 1);
    let replacement = bindings.bindings.values().next().unwrap().bound;
    assert_ne!(bound, replacement);
    drop(bindings);
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
    let mut bindings = isolated_bindings();
    let loopback = loopback_interface();
    let snapshot = HashMap::from([(loopback.index, loopback.clone())]);
    bindings.scan(&snapshot);
    let original = bindings.bindings.values().next().unwrap().socket.clone();
    let bound = original.local_addr().unwrap();
    // A new device may reuse both index and name; hardware identity still changes.
    let mut changed = loopback.clone();
    changed.hw_addr.push_str("-replaced");
    bindings.scan(&HashMap::from([(changed.index, changed)]));
    assert_eq!(bindings.bindings.len(), 1);
    assert!(bindings.dock.find_socket(bound).is_none());
    assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
    let replacement = bindings.bindings.values().next().unwrap().socket.clone();
    assert!(!Arc::ptr_eq(&original, &replacement));

    let mut changed = loopback;
    changed.index = u32::MAX;
    bindings.scan(&HashMap::from([(changed.index, changed)]));
    assert!(
        bindings.bindings.is_empty(),
        "invalid interface cannot bind"
    );
    assert!(
        bindings
            .addresses
            .mdns_endpoints(replacement.local_addr().unwrap())
            .is_empty()
    );
    bindings.scan(&snapshot);
    assert_eq!(bindings.bindings.len(), 1);
}

#[tokio::test]
async fn registration_preserves_existing_owners_and_rolls_back_failed_publication() {
    let bindings = isolated_bindings();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    let direct = EndpointAddr::direct(bound);
    bindings.dock.add(socket.clone()).unwrap().unwrap();
    assert!(bindings.register(socket.clone()).unwrap().is_none());
    assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
    assert!(bindings.dock.find_socket(bound).is_some());
    bindings.dock.remove(&socket);
    bindings.addresses.insert_inner(&socket, direct).unwrap();
    assert!(bindings.register(socket.clone()).is_err());
    assert!(bindings.dock.find_socket(bound).is_none());
    assert!(
        bindings
            .dock
            .topology()
            .quic()
            .find_socket(direct)
            .is_none()
    );
    assert_eq!(bindings.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    bindings.addresses.remove_bound(bound);
    let registration = bindings.register(socket).unwrap().unwrap();
    assert_eq!(bindings.addresses.mdns_endpoints(bound).as_ref(), &[direct]);
    bindings.withdraw(&registration);
}

#[tokio::test]
async fn scan_withdraws_and_rebinds_after_receiver_exit_or_abort() {
    use qbase::{datagram::forward::Payload, net::route::Pathway};
    for abort in [false, true] {
        let mut bindings = isolated_bindings();
        let loopback = loopback_interface();
        let snapshot = HashMap::from([(loopback.index, loopback)]);
        bindings.scan(&snapshot);
        let binding = bindings.bindings.values().next().unwrap();
        let socket = binding.socket.clone();
        let bound = binding.bound;
        let receiver = binding.receiver.clone();
        if abort {
            receiver.abort();
        } else {
            // Force a real receive-loop error by forwarding IPv6 through IPv4.
            bindings.dock.topology().forward().serve(bound, &socket);
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
            !bindings.addresses.mdns_endpoints(bound).is_empty(),
            "Dock leaves publication to Network"
        );
        bindings.scan(&snapshot);
        assert!(bindings.addresses.mdns_endpoints(bound).is_empty());
        assert!(bindings.dock.find_socket(bound).is_none());
        assert_eq!(bindings.bindings.len(), 1);
        assert_ne!(bindings.bindings.values().next().unwrap().bound, bound);
    }
}
