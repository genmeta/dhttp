//! Own device bindings and serialize interface scans, NAT polling and withdrawal.
mod nat;
#[cfg(test)]
#[path = "../../tests/support/interface_bindings.rs"]
mod test_support;
#[cfg(test)]
#[path = "../../tests/unit/network/interfaces.rs"]
mod tests;

use futures::{FutureExt, future::BoxFuture};
use nat::probe_nat;
use qbase::net::addr::EndpointAddr;
use qconn::Scope;
use qprotocol::{AddressBook, Dock, UdpSocket};
use qudp::BoundDevice;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

const BINDING_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Prepare the initial bindings before handing ownership to one maintenance task.
pub(super) async fn init() -> io::Result<()> {
    let mut watcher = netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>()
        .map_err(io::Error::other)?;
    qtransport::router::QuicRouter::global();
    let snapshot = watcher.changed().await.interfaces;
    let mut bindings =
        InterfaceBindings::new(Dock::global().clone(), AddressBook::global().clone());
    bindings.scan(&snapshot);
    tokio::spawn(watch(watcher, snapshot, bindings));
    Ok(())
}

/// A desired binding without a port. Hardware identity detects interface replacement
/// even when the OS reuses a name and index.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InterfaceAddress {
    name: String,
    index: u32,
    hw_addr: String,
    addr: SocketAddr,
}

struct Binding {
    bound: SocketAddr,
    socket: Arc<UdpSocket>,
    receiver: tokio::task::AbortHandle,
    nat_probe: BoxFuture<'static, ()>,
}

/// Only bindings created by this maintenance task belong to this table.
struct InterfaceBindings {
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    bindings: HashMap<InterfaceAddress, Binding>,
}

impl InterfaceBindings {
    fn new(dock: Arc<Dock>, addresses: Arc<AddressBook>) -> Self {
        Self {
            dock,
            addresses,
            bindings: HashMap::new(),
        }
    }

    fn register(&self, socket: Arc<UdpSocket>) -> io::Result<Option<Binding>> {
        let bound = socket.local_addr()?;
        let Some(receiver) = self.dock.add(socket.clone())? else {
            return Ok(None);
        };
        // Dock already registered the direct QUIC endpoint. Publication is our policy.
        let endpoint = EndpointAddr::direct(bound);
        let published = match endpoint.scope() {
            Some(Scope::External) => self.addresses.insert_outer(&socket, endpoint),
            Some(Scope::Loopback | Scope::Internal) => {
                self.addresses.insert_inner(&socket, endpoint)
            }
            None => Ok(()),
        };
        if let Err(error) = published {
            // AddressBook insertion is atomic; preserve any pre-existing publication.
            self.dock.remove(&socket);
            return Err(io::Error::other(error));
        }
        let nat_probe = if bound.ip().is_loopback()
            || matches!(bound.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            std::future::pending().boxed()
        } else {
            probe_nat(
                self.dock.clone(),
                self.addresses.clone(),
                socket.clone(),
                qprotocol::StunProtocol::stun_servers(),
            )
            .boxed()
        };
        Ok(Some(Binding {
            nat_probe,
            bound,
            socket,
            receiver,
        }))
    }

    fn withdraw(&self, binding: &Binding) {
        // Probe futures are polled only by watch, so no publication can race withdrawal.
        // Removing this Binding drops its future and outstanding STUN transactions.
        self.addresses.remove_bound(binding.bound);
        self.dock.remove(&binding.socket);
    }

    fn scan(&mut self, snapshot: &HashMap<u32, netwatcher::Interface>) {
        let current = interfaces(snapshot);
        let obsolete = self
            .bindings
            .iter()
            .filter_map(|(key, binding)| {
                let live = !binding.receiver.is_finished()
                    && self
                        .dock
                        .find_socket(binding.bound)
                        .is_some_and(|socket| Arc::ptr_eq(&socket, &binding.socket));
                (!live || !current.contains_key(key)).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in obsolete {
            let mut binding = self.bindings.remove(&key).unwrap();
            binding.nat_probe = std::future::pending().boxed();
            self.withdraw(&binding);
        }
        for (key, device) in current {
            if self.bindings.contains_key(&key) {
                continue;
            }
            match UdpSocket::bind_to_device(key.addr, device)
                .and_then(|socket| self.register(Arc::new(socket)))
            {
                Ok(Some(binding)) => {
                    self.bindings.insert(key, binding);
                }
                Ok(None) => tracing::warn!(addr = %key.addr, "socket address already registered"),
                Err(error) => {
                    tracing::warn!(addr = %key.addr, %error, "socket binding or publication failed")
                }
            }
        }
    }
}

impl Drop for InterfaceBindings {
    fn drop(&mut self) {
        for binding in self.bindings.values_mut() {
            binding.nat_probe = std::future::pending().boxed();
        }
        for binding in self.bindings.values() {
            self.withdraw(binding);
        }
    }
}

fn interfaces(
    snapshot: &HashMap<u32, netwatcher::Interface>,
) -> HashMap<InterfaceAddress, BoundDevice> {
    let mut current = HashMap::new();
    for interface in snapshot.values() {
        let device = match BoundDevice::new(interface.name.clone(), interface.index) {
            Ok(device) => device,
            Err(error) => {
                tracing::warn!(interface = %interface.name, %error, "interface unavailable");
                continue;
            }
        };
        for record in &interface.ips {
            let ip = record.ip;
            if ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let addr = match ip {
                IpAddr::V4(ip) => SocketAddr::new(ip.into(), 0),
                IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    0,
                    0,
                    if ip.is_unicast_link_local() {
                        interface.index
                    } else {
                        0
                    },
                )),
            };
            current.insert(
                InterfaceAddress {
                    name: interface.name.clone(),
                    index: interface.index,
                    hw_addr: interface.hw_addr.clone(),
                    addr,
                },
                device.clone(),
            );
        }
    }
    current
}

async fn watch(
    mut watcher: netwatcher::AsyncWatch,
    mut snapshot: HashMap<u32, netwatcher::Interface>,
    mut bindings: InterfaceBindings,
) {
    let mut check = tokio::time::interval_at(
        tokio::time::Instant::now() + BINDING_CHECK_INTERVAL,
        BINDING_CHECK_INTERVAL,
    );
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        bindings.scan(&snapshot);
        tokio::select! {
            biased;
            update = watcher.changed() => snapshot = update.interfaces,
            _ = check.tick() => {}
            _ = std::future::poll_fn(|cx| {
                // Scan before polling: a ready old measurement cannot revive a dead binding.
                // No future owns a separate publishing task.
                for binding in bindings.bindings.values_mut() {
                    if binding.nat_probe.poll_unpin(cx).is_ready() {
                        // Completed probes must not be polled again.
                        binding.nat_probe = std::future::pending().boxed();
                    }
                }
                std::task::Poll::<()>::Pending
            }) => {}
        }
    }
}
