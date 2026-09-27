use dhttp::{DhttpNetwork, Error};

#[tokio::test]
async fn network_initializes_once() {
    assert!(matches!(
        DhttpNetwork::global(),
        Err(Error::NetworkNotInitialized)
    ));
    let (first, second) = tokio::join!(DhttpNetwork::init(), DhttpNetwork::init());
    let network = match (first, second) {
        (Ok(network), Err(Error::AlreadyInitialized))
        | (Err(Error::AlreadyInitialized), Ok(network)) => network,
        _ => panic!("exactly one concurrent initialization must succeed"),
    };
    assert!(
        qprotocol::Dock::global().is_empty(),
        "network binds no sockets before a server listens"
    );
    assert!(std::ptr::eq(network, DhttpNetwork::global().unwrap()));
    assert!(matches!(
        DhttpNetwork::init().await,
        Err(Error::AlreadyInitialized)
    ));
}
