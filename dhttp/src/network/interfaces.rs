//! Own network interfaces and bindings; serialize scans, recovery, NAT polling and withdrawal.
mod nat;
#[cfg(test)]
#[path = "../../tests/support/interface_bindings.rs"]
mod test_support;
#[cfg(test)]
#[path = "../../tests/unit/network/interfaces.rs"]
mod tests;

use futures::FutureExt;
use qbase::net::addr::EndpointAddr;
use qconn::Scope;
use qprotocol::{AddressBook, Dock, UdpSocket};
use qudp::BoundDevice;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

const BINDING_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Shared network interfaces and bindings, accessed by recovery and background polling.
/// The mutex is held only for synchronous state changes, never across an await.
pub(super) struct Interfaces {
    state: Arc<Mutex<Option<InterfacesCtx>>>,
}

struct InterfacesCtx {
    watcher: netwatcher::AsyncWatch,
    snapshot: HashMap<u32, netwatcher::Interface>,
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    /// Only bindings created by Interfaces belong to this table.
    bindings: HashMap<InterfaceAddress, Binding>,
    check: tokio::time::Interval,
    waker: Option<Waker>,
}

impl Interfaces {
    /// Prepare the initial bindings before starting background polling.
    pub(super) async fn init() -> io::Result<Self> {
        let mut watcher = netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>()
            .map_err(io::Error::other)?;
        qtransport::router::QuicRouter::global();
        let snapshot = watcher.changed().await.interfaces;
        let mut state = InterfacesCtx::new(
            watcher,
            snapshot,
            Dock::global().clone(),
            AddressBook::global().clone(),
        );
        state.scan();
        let (interfaces, _task) = Self::start(state);
        Ok(interfaces)
    }

    fn start(state: InterfacesCtx) -> (Self, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(Some(state)));
        // Construct cleanup before spawning so cancellation before the first poll
        // also withdraws bindings and marks interface polling as stopped.
        let cleanup = scopeguard::guard(state.clone(), |state| {
            state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
        });
        let task = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                let mut state = cleanup.lock().unwrap();
                match state.as_mut() {
                    Some(state) => state.poll(cx),
                    None => Poll::Ready(()),
                }
            })
            .await;
        });
        (Self { state }, task)
    }

    /// Refresh the watcher, repair bindings and restart NAT measurements directly.
    pub(super) async fn resume(&self) -> crate::Result<()> {
        if self.state.lock().map_err(|_| Self::stopped())?.is_none() {
            return Err(Self::stopped().into());
        }
        let mut watcher = netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>()
            .map_err(io::Error::other)?;
        // Android's initial replay can be cached. Subscribe before enumerating,
        // and keep the previous state intact if either preparation step fails.
        let _ = watcher.changed().await;
        let waker = {
            let mut state = self.state.lock().map_err(|_| Self::stopped())?;
            let state = state.as_mut().ok_or_else(Self::stopped)?;
            // Enumerate under the same lock as background updates so concurrent
            // calls and old OS notifications cannot apply an earlier snapshot.
            let snapshot = netwatcher::list_interfaces().map_err(io::Error::other)?;
            state.watcher = watcher;
            state.snapshot = snapshot;
            state.scan();
            for binding in state.bindings.values_mut() {
                if let Some(nat) = &mut binding.nat {
                    nat.resume(qprotocol::StunProtocol::stun_servers());
                }
            }
            state.waker.clone()
        };
        // Poll the new watcher and NAT futures immediately to register their wakes.
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn stopped() -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "network maintenance task stopped",
        )
    }
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
    nat: Option<nat::Nat>,
}

impl InterfacesCtx {
    fn new(
        watcher: netwatcher::AsyncWatch,
        snapshot: HashMap<u32, netwatcher::Interface>,
        dock: Arc<Dock>,
        addresses: Arc<AddressBook>,
    ) -> Self {
        let mut check = tokio::time::interval_at(
            tokio::time::Instant::now() + BINDING_CHECK_INTERVAL,
            BINDING_CHECK_INTERVAL,
        );
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            watcher,
            snapshot,
            dock,
            addresses,
            bindings: HashMap::new(),
            check,
            waker: None,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.waker = Some(cx.waker().clone());
        if std::pin::pin!(self.watcher.changed())
            .poll_unpin(cx)
            .is_ready()
        {
            // Old mobile notifications are only triggers to read current interfaces.
            match netwatcher::list_interfaces() {
                Ok(current) => self.snapshot = current,
                Err(error) => tracing::warn!(%error, "interface enumeration failed"),
            }
            // Register for the next notification on the next poll.
            cx.waker().wake_by_ref();
        }
        if self.check.poll_tick(cx).is_ready() {
            // Register the timer's next deadline after consuming this tick.
            cx.waker().wake_by_ref();
        }
        // Scan before polling: a ready old measurement cannot revive a dead binding.
        self.scan();
        for binding in self.bindings.values_mut() {
            if let Some(nat) = &mut binding.nat {
                let _ = nat.poll_unpin(cx);
            }
        }
        Poll::Pending
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
        let nat = if bound.ip().is_loopback()
            || matches!(bound.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            None
        } else {
            Some(nat::Nat::new(
                self.dock.clone(),
                self.addresses.clone(),
                socket.clone(),
                bound,
                qprotocol::StunProtocol::stun_servers(),
            ))
        };
        Ok(Some(Binding {
            nat,
            bound,
            socket,
            receiver,
        }))
    }

    fn remove(&self, binding: &Binding) {
        // The interface state lock serializes polling and withdrawal; publication cannot race.
        // Removing this Binding drops its future and outstanding STUN transactions.
        self.addresses.remove_bound(binding.bound);
        self.dock.remove(&binding.socket);
    }

    fn scan(&mut self) {
        let current = interfaces(&self.snapshot);
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
            binding.nat = None;
            self.remove(&binding);
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

impl Drop for InterfacesCtx {
    fn drop(&mut self) {
        for binding in self.bindings.values_mut() {
            binding.nat = None;
        }
        for binding in self.bindings.values() {
            self.remove(binding);
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
