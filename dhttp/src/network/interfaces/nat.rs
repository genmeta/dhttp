//! One-shot NAT classification, STUN heartbeats and mapping publication.
//!
//! A binding owns and polls its NAT state. Classification finishes before any
//! heartbeat contacts the STUN servers; dropping the binding cancels both stages.
//! Mapping updates register QUIC endpoints before publishing them and restore the
//! previous endpoints if registration or publication fails.
use futures::{FutureExt, future::BoxFuture};
use qbase::net::{NatType, addr::EndpointAddr};
use qprotocol::{AddressBook, Dock, StunProtocol, UdpSocket};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

const NAT_PROBE_TIMEOUT: Duration = Duration::from_secs(45);
const STUN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const STUN_DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(20);
const MAPPING_TIMEOUT: Duration = Duration::from_secs(10);
const NAT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

/// STUN server address -> observed outer address for the bound socket.
type OuterAddrMappings = HashMap<SocketAddr, SocketAddr>;

/// NAT state owned and polled directly by the interface maintenance task.
pub(super) struct Nat {
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    socket: Arc<UdpSocket>,
    probe: Probe,
}

enum Probe {
    Initial(BoxFuture<'static, Vec<SocketAddr>>),
    NatProbe {
        servers: Vec<SocketAddr>,
        nat_type: BoxFuture<'static, Option<NatType>>,
    },
    Heartbeat {
        servers: Vec<SocketAddr>,
        nat_type: Option<NatType>,
        // Preserve applied mappings when resume cancels an in-flight measurement.
        mappings: OuterAddrMappings,
        interval: tokio::time::Interval,
        measurement: Option<BoxFuture<'static, OuterAddrMappings>>,
    },
}

impl Probe {
    /// Resolve servers of the socket's address family, retrying after failure or timeout.
    fn initial<F>(
        bound: SocketAddr,
        servers: impl Future<Output = io::Result<Arc<[SocketAddr]>>> + Send + 'static,
        mut retry: impl FnMut() -> F + Send + 'static,
    ) -> Self
    where
        F: Future<Output = io::Result<Arc<[SocketAddr]>>> + Send,
    {
        Self::Initial(
            async move {
                let mut initial = Some(servers);
                loop {
                    let result = match initial.take() {
                        Some(servers) => {
                            tokio::time::timeout(STUN_DISCOVERY_TIMEOUT, servers).await
                        }
                        None => tokio::time::timeout(STUN_DISCOVERY_TIMEOUT, retry()).await,
                    };
                    match result {
                        Ok(Ok(servers)) => {
                            let servers: Vec<_> = servers
                                .iter()
                                .copied()
                                .filter(|server| server.is_ipv4() == bound.is_ipv4())
                                .collect();
                            if !servers.is_empty() {
                                return servers;
                            }
                            tracing::warn!(%bound, "no STUN server for socket address family");
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(%bound, %error, "STUN server discovery failed")
                        }
                        Err(error) => {
                            tracing::warn!(%bound, %error, "STUN server discovery timed out")
                        }
                    }
                    tokio::time::sleep(STUN_DISCOVERY_RETRY_INTERVAL).await;
                }
            }
            .boxed(),
        )
    }

    /// Classification failure still allows the binding to maintain outer addresses.
    fn nat_probe(stun: Arc<StunProtocol>, bound: SocketAddr, servers: Vec<SocketAddr>) -> Self {
        let server = servers[0];
        let nat_type = async move {
            match tokio::time::timeout(NAT_PROBE_TIMEOUT, stun.detect_nat(bound, server)).await {
                Ok(Ok(nat)) => Some(nat),
                Ok(Err(error)) => {
                    tracing::warn!(%bound, %error, "NAT classification failed");
                    None
                }
                Err(error) => {
                    tracing::warn!(%bound, %error, "NAT classification timed out");
                    None
                }
            }
        }
        .boxed();
        Self::NatProbe { servers, nat_type }
    }
}

impl Nat {
    pub(super) fn new(
        dock: Arc<Dock>,
        addresses: Arc<AddressBook>,
        socket: Arc<UdpSocket>,
        bound: SocketAddr,
        servers: impl Future<Output = io::Result<Arc<[SocketAddr]>>> + Send + 'static,
    ) -> Self {
        Self {
            dock,
            addresses,
            socket,
            probe: Probe::initial(bound, servers, StunProtocol::stun_servers),
        }
    }

    pub(super) fn resume(
        &mut self,
        servers: impl Future<Output = io::Result<Arc<[SocketAddr]>>> + Send + 'static,
    ) {
        let Ok(bound) = self.socket.local_addr() else {
            return;
        };
        match &mut self.probe {
            Probe::Initial(_) => {
                self.probe = Probe::initial(bound, servers, StunProtocol::stun_servers);
            }
            Probe::NatProbe { servers, .. } => {
                self.probe = Probe::nat_probe(
                    self.dock.topology().stun().clone(),
                    bound,
                    std::mem::take(servers),
                );
            }
            Probe::Heartbeat {
                interval,
                measurement,
                ..
            } => {
                interval.reset_immediately();
                *measurement = None;
            }
        }
    }
}

impl Future for Nat {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let Ok(bound) = this.socket.local_addr() else {
            return Poll::Pending;
        };
        if ensure_registered_socket(&this.dock, bound, &this.socket).is_err() {
            // The interface watcher withdraws this binding and drops its NAT future.
            return Poll::Pending;
        }
        loop {
            match &mut this.probe {
                Probe::Initial(discovery) => {
                    let servers = ready!(discovery.poll_unpin(cx));
                    this.probe =
                        Probe::nat_probe(this.dock.topology().stun().clone(), bound, servers);
                }
                Probe::NatProbe {
                    servers,
                    nat_type: classification,
                } => {
                    let nat_type = ready!(classification.poll_unpin(cx));
                    if let Some(nat) = nat_type {
                        this.addresses.set_nat(bound, nat);
                        tracing::info!(%bound, ?nat, "NAT classification complete");
                    }
                    let mut interval = tokio::time::interval(NAT_HEARTBEAT_INTERVAL);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    this.probe = Probe::Heartbeat {
                        servers: std::mem::take(servers),
                        nat_type,
                        mappings: OuterAddrMappings::new(),
                        interval,
                        measurement: None,
                    };
                }
                Probe::Heartbeat {
                    servers,
                    nat_type,
                    mappings,
                    interval,
                    measurement,
                } => {
                    if measurement.is_none() {
                        ready!(interval.poll_tick(cx));
                        let stun = this.dock.topology().stun().clone();
                        let servers = servers.clone();
                        *measurement = Some(
                            async move {
                                // Failed servers are omitted so their old mappings are withdrawn.
                                futures::future::join_all(servers.into_iter().map(|server| {
                                    let stun = &stun;
                                    async move {
                                        let response = tokio::time::timeout(
                                            MAPPING_TIMEOUT,
                                            stun.detect_outer(bound, server),
                                        ).await;
                                        match response {
                                            Ok(Ok(Some(outer)))
                                                if outer.is_ipv4() == bound.is_ipv4()
                                                    && outer.port() != 0
                                                    && EndpointAddr::direct(outer).is_globally_routable() =>
                                            {
                                                Some((server, outer))
                                            }
                                            response => {
                                                tracing::warn!(
                                                    %bound, %server, ?response,
                                                    "STUN heartbeat failed or returned an unusable public mapping"
                                                );
                                                None
                                            }
                                        }
                                    }
                                }))
                                .await
                                .into_iter()
                                .flatten()
                                .collect()
                            }
                            .boxed(),
                        );
                    }
                    let refreshed = ready!(measurement.as_mut().unwrap().poll_unpin(cx));
                    *measurement = None;
                    if let Err(error) = apply_outer_mappings(
                        &this.dock,
                        &this.addresses,
                        &this.socket,
                        *nat_type,
                        mappings,
                        &refreshed,
                    ) {
                        tracing::warn!(%bound, %error, "NAT mapping synchronization failed");
                        continue;
                    }
                    *mappings = refreshed;
                    if let Some(nat) = *nat_type {
                        for (&server, &outer) in mappings.iter() {
                            tracing::debug!(%bound, ?nat, %server, %outer, "NAT mapping heartbeat");
                        }
                    } else if !mappings.is_empty() {
                        tracing::warn!(%bound, "STUN mappings maintained without a NAT classification");
                    }
                }
            }
        }
    }
}

/// Compare socket identity because the OS may reuse a withdrawn binding's address.
fn ensure_registered_socket(
    dock: &Dock,
    bound: SocketAddr,
    socket: &Arc<UdpSocket>,
) -> io::Result<()> {
    if dock
        .find_socket(bound)
        .is_some_and(|registered| Arc::ptr_eq(&registered, socket))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "NAT socket is no longer registered",
        ))
    }
}

/// Rebuild QUIC registrations, publish additions, then withdraw obsolete records.
/// QuicProtocol revokes all endpoints for a bound socket together, so rollback
/// must restore the direct binding as well as every previous mapped endpoint.
fn apply_outer_mappings(
    dock: &Dock,
    addresses: &AddressBook,
    socket: &Arc<UdpSocket>,
    nat_type: Option<NatType>,
    previous: &OuterAddrMappings,
    refreshed: &OuterAddrMappings,
) -> io::Result<()> {
    let bound = socket.local_addr()?;
    ensure_registered_socket(dock, bound, socket)?;
    if previous == refreshed {
        return Ok(());
    }

    let quic = dock.topology().quic();
    // QUIC accepts the direct binding, direct public mappings and agent-mediated paths.
    let registered_endpoints = |mappings: &OuterAddrMappings| {
        let mut endpoints = vec![EndpointAddr::direct(bound)];
        for (&server, &outer) in mappings {
            endpoints.push(EndpointAddr::direct(outer));
            endpoints.push(EndpointAddr::mediate(server, outer));
        }
        endpoints.sort_unstable();
        endpoints.dedup();
        endpoints
    };
    // Every mapping retains its STUN agent; FullCone also advertises a direct path.
    let published_endpoints = |mappings: &OuterAddrMappings| -> HashSet<EndpointAddr> {
        mappings
            .iter()
            .flat_map(|(&agent, &outer)| {
                // Preserve Mediate so the E record encodes outer-agent, even for FullCone.
                std::iter::once(EndpointAddr::mediate(agent, outer)).chain(
                    (nat_type == Some(NatType::FullCone)).then_some(EndpointAddr::direct(outer)),
                )
            })
            .filter(|endpoint| *endpoint != EndpointAddr::direct(bound))
            .collect()
    };
    let desired = registered_endpoints(refreshed);
    // Reject known conflicts before removing any of our current registrations.
    for &endpoint in &desired {
        if quic
            .find_socket(endpoint)
            .is_some_and(|owner| !Arc::ptr_eq(&owner, socket))
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("NAT endpoint already in use: {endpoint}"),
            ));
        }
    }

    let old = published_endpoints(previous);
    let new = published_endpoints(refreshed);
    let mut added = Vec::new();
    quic.unregister(bound);
    let update = (|| -> io::Result<()> {
        for endpoint in desired {
            quic.register(endpoint, socket).map_err(io::Error::other)?;
        }
        for &endpoint in new.difference(&old) {
            addresses
                .insert_outer(socket, endpoint)
                .map_err(io::Error::other)?;
            added.push(endpoint);
        }
        Ok(())
    })();
    if let Err(error) = update {
        quic.unregister(bound);
        for endpoint in registered_endpoints(previous) {
            let _ = quic.register(endpoint, socket);
        }
        for endpoint in added {
            addresses.remove(endpoint);
        }
        return Err(error);
    }
    for &endpoint in old.difference(&new) {
        addresses.remove(endpoint);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/network/nat.rs"]
mod tests;
