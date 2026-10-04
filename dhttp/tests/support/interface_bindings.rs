use super::*;

pub(super) fn isolated_bindings() -> InterfaceBindings {
    InterfaceBindings::new(
        Dock::new(Arc::new(qprotocol::topology::Topology::new(
            Arc::new(qprotocol::StunProtocol::new()),
            Arc::new(qprotocol::ForwardProtocol::new()),
            Arc::new(qprotocol::QuicProtocol::new()),
        ))),
        Arc::new(AddressBook::new()),
    )
}
