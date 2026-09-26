fn clear_bindings(network: &DhttpNetwork) {
    let mut bindings = network.bindings.lock().unwrap();
    for (_, binding) in bindings.drain() {
        withdraw_binding(network, binding);
    }
}
fn withdraw_binding(network: &DhttpNetwork, binding: Binding) {
    if let Ok(actual) = binding.socket.local_addr() {
        network.addresses.remove_bound(actual);
        QuicProtocol::global().unregister(EndpointAddr::direct(actual), &binding.socket);
    }
    Dock::global().remove(&binding.socket);
}
fn update_bindings(network: &DhttpNetwork) {
    let devices = netdev::get_interfaces();
    let mut selected = HashMap::new();
    for rule in &network.config.listen {
        for device in devices.iter().filter(|device| device.is_up()) {
            let scopes = match rule {
                ListenConfig::Scope(scopes) => *scopes,
                ListenConfig::Interface {
                    device: name,
                    scopes,
                } if *name == device.name => *scopes,
                _ => continue,
            };
            for address in device
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .chain(device.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
            {
                if address.is_unspecified() || address.is_multicast() {
                    continue;
                }
                let effective = if device.is_loopback() {
                    if scopes.contains(Scope::Loopback) {
                        Scopes::from(Scope::Loopback)
                    } else {
                        continue;
                    }
                } else {
                    let external = scopes.contains(Scope::External)
                        && !matches!(address, IpAddr::V4(ip) if ip.is_link_local())
                        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local());
                    match (scopes.contains(Scope::Internal), external) {
                        (true, true) => Scope::Internal | Scope::External,
                        (true, false) => Scope::Internal.into(),
                        (false, true) => Scope::External.into(),
                        _ => continue,
                    }
                };
                selected
                    .entry((device.name.clone(), address))
                    .and_modify(|value: &mut (Scopes, u32)| value.0 = value.0 | effective)
                    .or_insert((effective, device.index));
            }
        }
    }
    let mut bindings = network.bindings.lock().unwrap();
    if network.stop.is_cancelled() {
        return;
    }
    let stale = bindings
        .iter()
        .filter(|(key, value)| selected.get(*key) != Some(&(value.scopes, value.device_index)))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in stale {
        if let Some(binding) = bindings.remove(&key) {
            withdraw_binding(network, binding);
        }
    }
    for ((device, address), (scopes, device_index)) in selected {
        if bindings.contains_key(&(device.clone(), address)) {
            continue;
        }
        let bound = match address {
            IpAddr::V4(ip) => SocketAddr::new(ip.into(), 0),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                ip,
                0,
                0,
                if ip.is_unicast_link_local() {
                    device_index
                } else {
                    0
                },
            )),
        };
        let Ok(bound_device) = qudp::BoundDevice::new(&device, device_index) else {
            continue;
        };
        let Ok(socket) = UdpSocket::bind_to_device(bound, bound_device).map(Arc::new) else {
            continue;
        };
        let Ok(actual) = socket.local_addr() else {
            continue;
        };
        if !Dock::global().add(socket.clone()).unwrap_or(false) {
            continue;
        }
        let endpoint = EndpointAddr::direct(actual);
        if QuicProtocol::global().register(endpoint, &socket).is_err() {
            Dock::global().remove(&socket);
            continue;
        }
        if scopes.contains(Scope::Internal) || scopes.contains(Scope::Loopback) {
            let _ = network.addresses.insert_inner(actual, endpoint);
        }
        bindings.insert(
            (device, address),
            Binding {
                socket,
                scopes,
                device_index,
            },
        );
    }
}

fn validate_config(config: &NetworkConfig, devices: &[netdev::Interface]) -> Result<()> {
    if config.listen.is_empty() {
        return Err(Error::InvalidNetworkConfig {
            message: "listen rules are empty".into(),
        });
    }
    for rule in &config.listen {
        let (scopes, device) = match rule {
            ListenConfig::Scope(scopes) => (*scopes, None),
            ListenConfig::Interface { device, scopes } => (*scopes, Some(device)),
        };
        if ![Scope::Loopback, Scope::Internal, Scope::External]
            .into_iter()
            .any(|scope| scopes.contains(scope))
        {
            return Err(Error::InvalidNetworkConfig {
                message: "a listen rule has no scopes".into(),
            });
        }
        if let Some(name) = device {
            let Some(found) = devices.iter().find(|candidate| candidate.name == *name) else {
                return Err(Error::InvalidNetworkConfig {
                    message: format!("interface {name} does not exist"),
                });
            };
            if (found.is_loopback()
                && (scopes.contains(Scope::Internal) || scopes.contains(Scope::External)))
                || (!found.is_loopback() && scopes.contains(Scope::Loopback))
            {
                return Err(Error::InvalidNetworkConfig {
                    message: format!("interface {name} is incompatible with its scopes"),
                });
            }
        }
    }
    Ok(())
}
