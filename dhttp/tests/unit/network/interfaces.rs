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
                    "255.255.255.255",
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

#[test]
fn interface_snapshot_preserves_platform_names_and_virtual_networks() {
    let names = [
        "p2p0",
        "",
        "lo",
        "lo0",
        "en0",
        // Raspberry Pi onboard, predictable, USB Ethernet/Wi-Fi and gadget names.
        "eth0",
        "eth1",
        "end0",
        "end1",
        "eno1",
        "enx001122aabbcc",
        "enp1s0u2",
        "usb0",
        "usb1",
        "wlx001122aabbcc",
        "wlan1",
        "bnep0",
        "lan0",
        "ens192",
        "enp3s0",
        "wlan0",
        "wlp2s0",
        "rmnet_data0",
        "pdp_ip0",
        "wwan0",
        "Ethernet",
        "Wi-Fi",
        "tun0",
        "tap0",
        "utun4",
        "wg0",
        "tailscale0",
        "ztabcdef",
        "br0",
        "vmnet0",
        "vEthernet (External Switch)",
        "br-office",
        "docker-uplink",
        "veth-uplink",
        "veth",
        "cni",
        "以太网",
        "无线网络连接",
        "Ethernet 2",
        "Docker0",
        "bridge",
        "bridge-office",
        "bridge100-uplink",
        "awdl",
        "awdl-uplink",
        "llw",
        "llw0-uplink",
        "Bridge100",
    ];
    for name in names {
        for os in ["macos", "ios", "linux", "android", "windows", "freebsd"] {
            assert!(!excluded_interface(name, os), "interface {name:?} on {os}");
        }
        // Preserve other networks and prefix lookalikes, regardless of MAC visibility.
        let interface = netwatcher::Interface {
            index: 7,
            name: name.into(),
            hw_addr: String::new(),
            ips: ["192.168.1.2", "192.168.215.0", "fd00::1", "fe80::1"]
                .map(|ip| netwatcher::IpRecord {
                    ip: ip.parse().unwrap(),
                    prefix_len: 64,
                })
                .into(),
        };
        let current = interfaces(&HashMap::from([(7, interface)]));
        assert_eq!(current.len(), 4, "interface {name:?}");
        assert!(current.iter().all(|(key, device)| {
            key.name == name && device.name() == name && device.index().get() == 7
        }));
        assert!(
            current
                .keys()
                .any(|key| key.addr == "[fe80::1%7]:0".parse().unwrap())
        );
    }
}

#[test]
fn interface_snapshot_excludes_auxiliary_names_only_on_matching_platforms() {
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["macos", "ios"],
            &[
                "bridge0",
                "bridge100",
                "bridge101",
                "awdl0",
                "awdl12",
                "llw0",
                "llw12",
            ],
        ),
        (
            &["macos", "ios", "linux", "android"],
            &["vboxnet0", "vboxnet12", "vmnet1", "vmnet8"],
        ),
        (
            &["linux", "android"],
            &[
                "docker0",
                "docker1",
                "docker_gwbridge",
                "podman0",
                "br-012345abcdef",
                "veth012abc",
                "veth0",
                "cni0",
                "flannel.1",
                "kube-ipvs0",
                "virbr0",
                "virbr0-nic",
                "dummy0",
                "ifb0",
            ],
        ),
        (
            &["windows"],
            &[
                "vEthernet (Default Switch)",
                "vEthernet (DockerNAT)",
                "vEthernet (WSL)",
                "vEthernet (WSL (Hyper-V firewall))",
                "VMware Network Adapter VMnet1",
                "VMware Network Adapter VMnet8",
                "VirtualBox Host-Only Ethernet Adapter",
                "VirtualBox Host-Only Ethernet Adapter #2",
                "VirtualBox Host-Only Network",
                "VirtualBox Host-Only Network #3",
                "VETHERNET (WSL)",
            ],
        ),
    ];
    for &(excluded_on, names) in cases {
        for &name in names {
            for os in ["macos", "ios", "linux", "android", "windows", "freebsd"] {
                assert_eq!(
                    excluded_interface(name, os),
                    excluded_on.contains(&os),
                    "{name:?} on {os}"
                );
            }
            let interface = netwatcher::Interface {
                index: 7,
                name: name.into(),
                hw_addr: String::new(),
                ips: ["192.168.215.0", "fd00::1", "fe80::1"]
                    .map(|ip| netwatcher::IpRecord {
                        ip: ip.parse().unwrap(),
                        prefix_len: 64,
                    })
                    .into(),
            };
            let current = interfaces(&HashMap::from([(7, interface)]));
            assert_eq!(
                current.len(),
                if excluded_on.contains(&std::env::consts::OS) {
                    0
                } else {
                    3
                },
                "interface {name:?}"
            );
        }
    }
}

#[test]
fn linux_preserves_generic_bridges_and_custom_interface_names() {
    // Raspberry Pi bridge/hotspot setups may put the host address on bridge0.
    for name in [
        "br0",
        "bridge0",
        "bridge100",
        "br-lan",
        "br-office",
        "br-deadbeef",
        "br-012345abcdeg",
        "docker-uplink",
        "docker",
        "veth-uplink",
        "veth",
        "cni",
        "virbr-office",
        "vmnet0",
        "vEthernet (External Switch)",
        "my-uplink",
    ] {
        assert!(!excluded_interface(name, "linux"), "{name}");
    }
}

#[test]
fn nat_probes_preserve_private_networks_but_skip_local_only_addresses() {
    for ip in ["127.0.0.1", "127.1.2.3", "::1", "169.254.1.2", "fe80::1"] {
        assert!(!supports_nat_probe(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.2",
        "100.64.0.1",
        "fd00::1",
        "8.8.8.8",
        "2001:4860::1",
    ] {
        assert!(supports_nat_probe(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn identical_ipv6_link_local_addresses_keep_distinct_interface_scopes() {
    let snapshot = [7, 11].map(|index| {
        (
            index,
            netwatcher::Interface {
                index,
                name: format!("device{index}"),
                hw_addr: String::new(),
                // Duplicate OS records collapse within a device, never across devices.
                ips: vec![
                    netwatcher::IpRecord {
                        ip: "fe80::1".parse().unwrap(),
                        prefix_len: 64,
                    };
                    2
                ],
            },
        )
    });
    let current = interfaces(&snapshot.into());
    assert_eq!(current.len(), 2);
    for key in current.keys() {
        let SocketAddr::V6(addr) = key.addr else {
            panic!("expected an IPv6 binding");
        };
        assert_eq!(addr.scope_id(), key.index);
    }
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
async fn failed_address_binding_does_not_remove_usable_bindings_on_the_device() {
    let mut state = isolated_interfaces().await;
    let loopback = loopback_interface();
    state.snapshot = HashMap::from([(loopback.index, loopback.clone())]);
    state.scan();
    let socket = state.bindings.values().next().unwrap().socket.clone();
    let bound = socket.local_addr().unwrap();

    let mut unavailable = loopback;
    // IPV6_V6ONLY sockets reject mapped IPv4 addresses on all supported platforms.
    unavailable.ips.push(netwatcher::IpRecord {
        ip: "::ffff:127.0.0.1".parse().unwrap(),
        prefix_len: 128,
    });
    state.snapshot = HashMap::from([(unavailable.index, unavailable)]);
    state.scan();
    assert_eq!(state.bindings.len(), 1);
    assert!(Arc::ptr_eq(
        &socket,
        &state.dock.find_socket(bound).unwrap()
    ));
    assert!(!state.addresses.mdns_endpoints(bound).is_empty());
}

#[tokio::test]
async fn scan_withdraws_bindings_when_device_loses_usable_addresses() {
    let mut state = isolated_interfaces().await;
    let loopback = loopback_interface();
    state.snapshot = HashMap::from([(loopback.index, loopback.clone())]);
    state.scan();
    let bound = state.bindings.values().next().unwrap().bound;
    let endpoint = EndpointAddr::direct(bound);

    let mut unavailable = loopback.clone();
    unavailable.ips = ["0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "ff02::1"]
        .map(|ip| netwatcher::IpRecord {
            ip: ip.parse().unwrap(),
            prefix_len: 0,
        })
        .into();
    state.snapshot = HashMap::from([(unavailable.index, unavailable)]);
    state.scan();
    assert!(state.bindings.is_empty());
    assert!(state.dock.find_socket(bound).is_none());
    assert!(state.dock.topology().quic().find_socket(endpoint).is_none());
    assert!(state.addresses.mdns_endpoints(bound).is_empty());

    state.snapshot = HashMap::from([(loopback.index, loopback)]);
    state.scan();
    assert_eq!(state.bindings.len(), 1);
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
    // A zero index is invalid on every platform. An arbitrary nonzero index
    // may bind successfully on Linux before packet-info validation at send time.
    changed.index = 0;
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
