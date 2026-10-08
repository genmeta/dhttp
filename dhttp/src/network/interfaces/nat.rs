//! One-shot NAT classification, STUN heartbeats and mapping publication.
//!
//! A binding owns and polls its probe future. Classification finishes before any
//! heartbeat contacts the STUN servers; dropping the binding cancels both stages.
//! Mapping updates register QUIC endpoints before publishing them and restore the
//! previous endpoints if registration or publication fails.
use qbase::net::{NatType, addr::EndpointAddr};
use qprotocol::{AddressBook, Dock, StunProtocol, UdpSocket};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

const NAT_PROBE_TIMEOUT: Duration = Duration::from_secs(45);
const STUN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MAPPING_TIMEOUT: Duration = Duration::from_secs(10);
const NAT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

/// Each STUN server observes its own public mapping for the bound socket.
type NatMappings = HashMap<SocketAddr, SocketAddr>;

pub(super) async fn probe_nat(
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    socket: Arc<UdpSocket>,
    servers: impl Future<Output = io::Result<Arc<[SocketAddr]>>> + Send + 'static,
) {
    let bound = match socket.local_addr() {
        Ok(bound) => bound,
        Err(error) => {
            tracing::warn!(%error, "NAT socket address unavailable");
            return;
        }
    };
    let Some(servers) = discover_stun_servers(bound, servers).await else {
        return;
    };
    let stun = dock.topology().stun();
    // Classify once before heartbeats create mappings at the other STUN nodes.
    let nat = classify_nat(stun, bound, servers[0]).await;
    if ensure_registered_socket(&dock, bound, &socket).is_err() {
        return;
    }
    if let Some(nat) = nat {
        addresses.set_nat(bound, nat);
        tracing::info!(%bound, ?nat, "NAT classification complete");
    }

    let mut mappings = NatMappings::new();
    let mut heartbeat = tokio::time::interval(NAT_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // The first tick is immediate; subsequent ticks maintain the mappings.
        heartbeat.tick().await;
        let refreshed = refresh_nat_mappings(stun, bound, &servers).await;
        if let Err(error) = apply_nat_mappings(&dock, &addresses, &socket, &mappings, &refreshed) {
            tracing::warn!(%bound, %error, "NAT mapping synchronization failed");
            continue;
        }
        mappings = refreshed;
        if let Some(nat) = nat {
            for (&server, &outer) in &mappings {
                tracing::debug!(%bound, ?nat, %server, %outer, "NAT mapping heartbeat");
            }
        } else if !mappings.is_empty() {
            // Maintain mappings without inventing a classification for punch advertisements.
            tracing::warn!(%bound, "STUN mappings maintained without a NAT classification");
        }
    }
}

/// Resolve servers for this socket's address family, preserving discovery order.
async fn discover_stun_servers(
    bound: SocketAddr,
    servers: impl Future<Output = io::Result<Arc<[SocketAddr]>>>,
) -> Option<Vec<SocketAddr>> {
    let servers = match tokio::time::timeout(STUN_DISCOVERY_TIMEOUT, servers).await {
        Ok(Ok(servers)) => servers
            .iter()
            .copied()
            .filter(|server| server.is_ipv4() == bound.is_ipv4())
            .collect::<Vec<_>>(),
        Ok(Err(error)) => {
            tracing::warn!(%bound, %error, "STUN server discovery failed");
            return None;
        }
        Err(error) => {
            tracing::warn!(%bound, %error, "STUN server discovery timed out");
            return None;
        }
    };
    if servers.is_empty() {
        tracing::warn!(%bound, "no STUN server for socket address family");
        return None;
    }
    Some(servers)
}

/// A classification failure still allows the binding to maintain STUN mappings.
async fn classify_nat(
    stun: &Arc<StunProtocol>,
    bound: SocketAddr,
    server: SocketAddr,
) -> Option<NatType> {
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

/// Probe concurrently; failed servers are omitted so their old mappings are withdrawn.
async fn refresh_nat_mappings(
    stun: &Arc<StunProtocol>,
    bound: SocketAddr,
    servers: &[SocketAddr],
) -> NatMappings {
    let responses = futures::future::join_all(
        servers
            .iter()
            .map(|&server| async move { (server, probe_mapping(stun, bound, server).await) }),
    )
    .await;
    let mut mappings = NatMappings::new();
    for (server, result) in responses {
        match result {
            Ok(outer) => {
                mappings.insert(server, outer);
            }
            Err(error) => tracing::warn!(%bound, %server, %error, "STUN heartbeat failed"),
        }
    }
    mappings
}

async fn probe_mapping(
    stun: &Arc<StunProtocol>,
    bound: SocketAddr,
    server: SocketAddr,
) -> io::Result<SocketAddr> {
    let outer = tokio::time::timeout(MAPPING_TIMEOUT, stun.detect_outer(bound, server))
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "STUN heartbeat unanswered"))?;
    if outer.is_ipv4() != bound.is_ipv4()
        || outer.port() == 0
        || !EndpointAddr::direct(outer).is_globally_routable()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "STUN returned an unusable public mapping",
        ));
    }
    Ok(outer)
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
fn apply_nat_mappings(
    dock: &Dock,
    addresses: &AddressBook,
    socket: &Arc<UdpSocket>,
    previous: &NatMappings,
    refreshed: &NatMappings,
) -> io::Result<()> {
    let bound = socket.local_addr()?;
    ensure_registered_socket(dock, bound, socket)?;
    if previous == refreshed {
        return Ok(());
    }

    let quic = dock.topology().quic();
    let desired = registered_endpoints(bound, refreshed);
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

    let nat = addresses.nat(bound);
    let old = published_endpoints(bound, nat, previous);
    let new = published_endpoints(bound, nat, refreshed);
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
        for endpoint in registered_endpoints(bound, previous) {
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

/// QUIC accepts the direct binding, direct public mappings and agent-mediated paths.
fn registered_endpoints(bound: SocketAddr, mappings: &NatMappings) -> Vec<EndpointAddr> {
    let mut endpoints = vec![EndpointAddr::direct(bound)];
    for (&server, &outer) in mappings {
        endpoints.push(EndpointAddr::direct(outer));
        endpoints.push(EndpointAddr::mediate(server, outer));
    }
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints
}

/// Only FullCone mappings are advertised directly; others retain their STUN agent.
fn published_endpoints(
    bound: SocketAddr,
    nat: Option<NatType>,
    mappings: &NatMappings,
) -> HashSet<EndpointAddr> {
    mappings
        .iter()
        .map(|(&agent, &outer)| {
            if nat == Some(NatType::FullCone) {
                EndpointAddr::direct(outer)
            } else {
                // Preserve Mediate so the E record encodes outer-agent.
                EndpointAddr::mediate(agent, outer)
            }
        })
        .filter(|endpoint| *endpoint != EndpointAddr::direct(bound))
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/network/nat.rs"]
mod tests;
