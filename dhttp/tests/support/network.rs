use dhttp::{AddressBook, Scope, resolve::EndpointAddr};

/// Read the directory's initial subscription replay, without a dhttp address cache.
pub fn loopback_endpoints() -> Vec<EndpointAddr> {
    let mut events = AddressBook::global().subscribe_punch(Scope::Loopback);
    let mut endpoints = Vec::new();
    while let Ok(qprotocol::AddressEvent::Added { endpoint, .. }) = events.try_recv() {
        endpoints.push(endpoint);
    }
    endpoints.sort_unstable();
    endpoints
}
