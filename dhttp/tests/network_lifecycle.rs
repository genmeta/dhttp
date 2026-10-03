#[path = "support/network.rs"]
mod network;

use dhttp::{AddressBook, DhttpNetwork, Error, resolve::*};
use futures::{FutureExt, StreamExt};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct TestResolver(Arc<AtomicUsize>);
impl std::fmt::Display for TestResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("test resolver")
    }
}
impl Resolve for TestResolver {
    fn lookup<'a>(&'a self, _: &'a str, _: &'a str, _: Option<Family>) -> ResolveFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        async {
            Ok(futures::stream::iter([(
                Source::System,
                EndpointAddr::direct("127.0.0.1:4433".parse().unwrap()),
            )])
            .boxed())
        }
        .boxed()
    }
}

#[tokio::test]
async fn network_initializes_once() {
    assert!(matches!(
        DhttpNetwork::global(),
        Err(Error::NetworkNotInitialized)
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    Resolver::add(Arc::new(TestResolver(calls.clone())));
    let temporary = qprotocol::EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let temporary_bound = temporary.udp_socket().local_addr().unwrap();
    assert!(
        AddressBook::global()
            .mdns_endpoints(temporary_bound)
            .is_empty()
    );
    let (first, second) = tokio::join!(DhttpNetwork::init(), DhttpNetwork::init());
    let network = first.unwrap();
    assert!(std::ptr::eq(network, second.unwrap()));
    assert!(
        !qprotocol::Dock::global().is_empty(),
        "clients need sockets even without a listener"
    );
    let endpoints = network::loopback_endpoints();
    assert!(!endpoints.is_empty());
    for endpoint in endpoints {
        assert!(endpoint.addr().ip().is_loopback());
        assert!(
            qprotocol::QuicProtocol::global()
                .find_socket(endpoint)
                .is_some()
        );
        assert!(
            qprotocol::AddressBook::global()
                .mdns_endpoints(endpoint.addr())
                .contains(&endpoint)
        );
    }
    let records = Resolver::get()
        .lookup("injected.test", "", None)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "startup must preserve the globally registered resolver"
    );
    let peer = EndpointAddr::direct("127.0.0.1:4433".parse().unwrap());
    let pathways = AddressBook::global().pathways_to(peer, &Source::System);
    assert!(
        !pathways.is_empty(),
        "startup must publish usable client paths"
    );
    for pathway in pathways {
        let socket = qprotocol::QuicProtocol::global()
            .find_socket(pathway.local())
            .unwrap();
        let nic = socket.bound_device().unwrap();
        assert!(
            AddressBook::global()
                .pathways_to(
                    peer,
                    &Source::Mdns {
                        nic: Arc::from(nic.name()),
                        family: Family::V4,
                    }
                )
                .contains(&pathway),
            "AddressBook must retain the native socket's interface metadata"
        );
    }
    assert!(std::ptr::eq(network, DhttpNetwork::global().unwrap()));
    let before = network::loopback_endpoints();
    let bindings = qprotocol::Dock::global().len();
    assert!(std::ptr::eq(network, DhttpNetwork::init().await.unwrap()));
    assert_eq!(network::loopback_endpoints(), before);
    assert_eq!(qprotocol::Dock::global().len(), bindings);

    // Dock can lose a receiver without any interface update. The periodic check
    // must withdraw its stale publication and repair the still-current interface.
    let old = before
        .iter()
        .find(|endpoint| endpoint.addr().is_ipv4())
        .unwrap();
    let old_bound = old.addr();
    let socket = qprotocol::Dock::global().find_socket(old_bound).unwrap();
    assert!(qprotocol::Dock::global().remove(&socket));
    assert!(
        AddressBook::global()
            .mdns_endpoints(old_bound)
            .contains(old)
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !AddressBook::global().mdns_endpoints(old_bound).is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("watch must withdraw a dead binding without an interface event");
    let after = network::loopback_endpoints();
    assert!(
        after
            .iter()
            .any(|endpoint| endpoint.addr().ip() == old_bound.ip() && endpoint.addr() != old_bound)
    );
    for retained in before.iter().filter(|endpoint| *endpoint != old) {
        assert!(after.contains(retained), "live bindings keep their ports");
    }
    assert!(
        qprotocol::Dock::global()
            .find_socket(temporary_bound)
            .is_some()
    );
    assert!(
        AddressBook::global()
            .mdns_endpoints(temporary_bound)
            .is_empty()
    );
}
