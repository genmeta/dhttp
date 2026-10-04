//! One-shot NAT classification, STUN heartbeats and transactional mapping updates.
use qbase::net::{NatType, addr::EndpointAddr};
use qprotocol::{AddressBook, Dock, UdpSocket};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

const NAT_PROBE_TIMEOUT: Duration = Duration::from_secs(45);
const MAPPING_TIMEOUT: Duration = Duration::from_secs(10);
const NAT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

// The future itself owns the pending classification/heartbeat operations. It is never
// spawned, so dropping a binding cancels measurement before its addresses are reused.
pub(super) async fn probe_nat(
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    socket: Arc<UdpSocket>,
    servers: impl std::future::Future<Output = io::Result<Arc<[SocketAddr]>>> + Send + 'static,
) {
    let bound = match socket.local_addr() {
        Ok(bound) => bound,
        Err(error) => {
            tracing::warn!(%error, "NAT socket address unavailable");
            return;
        }
    };
    let servers = match tokio::time::timeout(MAPPING_TIMEOUT, servers).await {
        Ok(Ok(servers)) => servers
            .iter()
            .copied()
            .filter(|server| server.is_ipv4() == bound.is_ipv4())
            .collect::<Vec<_>>(),
        Ok(Err(error)) => {
            tracing::warn!(%bound, %error, "STUN server discovery failed");
            return;
        }
        Err(error) => {
            tracing::warn!(%bound, %error, "STUN server discovery timed out");
            return;
        }
    };
    let Some(&first) = servers.first() else {
        tracing::warn!(%bound, "no STUN server for socket address family");
        return;
    };
    let stun = dock.topology().stun().clone();
    // Classify only once, before any heartbeat contacts the other STUN nodes.
    let nat = match tokio::time::timeout(NAT_PROBE_TIMEOUT, stun.detect_nat(bound, first)).await {
        Ok(Ok(nat)) => Some(nat),
        Ok(Err(error)) => {
            tracing::warn!(%bound, %error, "NAT classification failed");
            None
        }
        Err(error) => {
            tracing::warn!(%bound, %error, "NAT classification timed out");
            None
        }
    };
    if !dock
        .find_socket(bound)
        .is_some_and(|registered| Arc::ptr_eq(&registered, &socket))
    {
        return;
    }
    if let Some(nat) = nat {
        addresses.set_nat(bound, nat);
        tracing::info!(%bound, ?nat, "NAT classification complete");
    }
    let mut mappings = HashMap::new();
    let mut heartbeat = tokio::time::interval(NAT_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        heartbeat.tick().await;
        let responses = futures::future::join_all(servers.iter().map(|&server| {
            let stun = &stun;
            async move {
                let result =
                    tokio::time::timeout(MAPPING_TIMEOUT, stun.detect_outer(bound, server))
                        .await
                        .map_err(io::Error::other)
                        .and_then(|result| result.map_err(io::Error::other))
                        .and_then(|outer| {
                            outer.ok_or_else(|| {
                                io::Error::new(io::ErrorKind::TimedOut, "STUN heartbeat unanswered")
                            })
                        })
                        .and_then(|outer| {
                            if outer.is_ipv4() == bound.is_ipv4()
                                && outer.port() != 0
                                && EndpointAddr::direct(outer).is_globally_routable()
                            {
                                Ok(outer)
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "STUN returned an unusable public mapping",
                                ))
                            }
                        });
                (server, result)
            }
        }))
        .await;
        let mut refreshed = HashMap::new();
        for (server, result) in responses {
            match result {
                Ok(outer) => {
                    refreshed.insert(server, outer);
                }
                Err(error) => tracing::warn!(%bound, %server, %error, "STUN heartbeat failed"),
            }
        }
        if let Err(error) = sync_nat_mappings(&dock, &addresses, &socket, &mappings, &refreshed) {
            tracing::warn!(%bound, %error, "NAT mapping synchronization failed");
            continue;
        }
        mappings = refreshed;
        if let Some(nat) = nat {
            for (&server, &outer) in &mappings {
                tracing::debug!(%bound, ?nat, %server, %outer, "NAT mapping heartbeat");
            }
        } else if !mappings.is_empty() {
            // Preserve the one-shot classification error; keep sending heartbeats
            // without inventing a NAT type for punch advertisements.
            tracing::warn!(%bound, "STUN mappings maintained without a NAT classification");
        }
    }
}

// dhttp owns mapped endpoint registration and publication. Register endpoints before
// publishing them; rebuild on mapping changes because QuicProtocol revokes all
// endpoint registrations for a bound socket together.
fn sync_nat_mappings(
    dock: &Dock,
    addresses: &AddressBook,
    socket: &Arc<UdpSocket>,
    previous: &HashMap<SocketAddr, SocketAddr>,
    refreshed: &HashMap<SocketAddr, SocketAddr>,
) -> io::Result<()> {
    let bound = socket.local_addr()?;
    if !dock
        .find_socket(bound)
        .is_some_and(|registered| Arc::ptr_eq(&registered, socket))
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "NAT socket is no longer registered",
        ));
    }
    if previous == refreshed {
        return Ok(());
    }
    let quic = dock.topology().quic();
    let endpoints = |mappings: &HashMap<SocketAddr, SocketAddr>| {
        let mut endpoints = vec![EndpointAddr::direct(bound)];
        for (&server, &outer) in mappings {
            endpoints.push(EndpointAddr::direct(outer));
            endpoints.push(EndpointAddr::mediate(server, outer));
        }
        endpoints.sort_unstable();
        endpoints.dedup();
        endpoints
    };
    let desired = endpoints(refreshed);
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
    quic.unregister(bound);
    for endpoint in desired {
        if let Err(error) = quic.register(endpoint, socket) {
            quic.unregister(bound);
            for old in endpoints(previous) {
                let _ = quic.register(old, socket);
            }
            return Err(io::Error::other(error));
        }
    }
    let publication = |mappings: &HashMap<SocketAddr, SocketAddr>| {
        mappings
            .iter()
            .map(|(&agent, &outer)| {
                if addresses.nat(bound) == Some(NatType::FullCone) {
                    EndpointAddr::direct(outer)
                } else {
                    // A mapped port behind filtering NAT is reached through its agent.
                    // Preserve the Mediate value so the E record encodes outer-agent.
                    EndpointAddr::mediate(agent, outer)
                }
            })
            .filter(|endpoint| *endpoint != EndpointAddr::direct(bound))
            .collect::<std::collections::HashSet<_>>()
    };
    let old = publication(previous);
    let new = publication(refreshed);
    let mut added = Vec::new();
    for &endpoint in new.difference(&old) {
        if let Err(error) = addresses.insert_outer(socket, endpoint) {
            quic.unregister(bound);
            for endpoint in endpoints(previous) {
                let _ = quic.register(endpoint, socket);
            }
            for endpoint in added {
                addresses.remove(endpoint);
            }
            return Err(io::Error::other(error));
        }
        added.push(endpoint);
    }
    for &endpoint in old.difference(&new) {
        addresses.remove(endpoint);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/network/nat.rs"]
mod tests;
