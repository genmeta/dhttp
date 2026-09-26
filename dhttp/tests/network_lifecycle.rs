use dhttp::{DhttpNetwork, Error, ListenConfig, NetworkConfig, Scope};

#[tokio::test]
async fn network_initializes_once_and_shuts_down() {
    assert!(matches!(
        DhttpNetwork::global(),
        Err(Error::NetworkNotInitialized)
    ));
    assert!(matches!(
        DhttpNetwork::init(NetworkConfig { listen: vec![] }).await,
        Err(Error::InvalidNetworkConfig { .. })
    ));
    let config = NetworkConfig {
        listen: vec![ListenConfig::Scope(Scope::Loopback.into())],
    };
    let (first, second) = tokio::join!(
        DhttpNetwork::init(config.clone()),
        DhttpNetwork::init(config.clone())
    );
    let network = match (first, second) {
        (Ok(network), Err(Error::AlreadyInitialized))
        | (Err(Error::AlreadyInitialized), Ok(network)) => network,
        _ => panic!("exactly one concurrent initialization must succeed"),
    };
    assert!(
        !qprotocol::Dock::global().is_empty(),
        "loopback socket is bound"
    );
    assert!(std::ptr::eq(network, DhttpNetwork::global().unwrap()));
    assert!(matches!(
        DhttpNetwork::init(config).await,
        Err(Error::AlreadyInitialized)
    ));
    network.shutdown().unwrap();
    assert!(
        qprotocol::Dock::global().is_empty(),
        "bound sockets are released"
    );
    network.shutdown().unwrap();
}
