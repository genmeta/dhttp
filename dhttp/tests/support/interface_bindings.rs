use super::*;

pub(super) async fn isolated_interfaces() -> InterfacesCtx {
    let mut watcher =
        netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>().unwrap();
    let _ = watcher.changed().await;
    InterfacesCtx::new(
        watcher,
        HashMap::new(),
        Dock::new(Arc::new(qprotocol::topology::Topology::new(
            Arc::new(qprotocol::StunProtocol::new()),
            Arc::new(qprotocol::ForwardProtocol::new()),
            Arc::new(qprotocol::QuicProtocol::new()),
        ))),
        Arc::new(AddressBook::new()),
    )
}
