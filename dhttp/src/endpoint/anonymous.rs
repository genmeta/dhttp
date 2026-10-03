//! Anonymous client setup belongs to dhttp; qconn's endpoint always has an identity.
use crate::{Error, Result};
use qbase::{
    cid::{ArcRemoteCids, ConnectionId, GenUniqueCid},
    error::{ErrorKind, QuicError},
    param::ParameterId,
    role::Role,
    time::{ArcConnIdle, DEFAULT_HEARTBEAT_INTERVAL},
    token::{ArcTokenRegistry, handy::NoopTokenRegistry},
};
use qconn::{
    ArcConnPhase, ArcLocalCids, ArcReliableFrames, CidRegistry, InitialPhase, Paths, TlsContext,
};
use qtransport::{packet::channel, router::QuicRouter};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;

pub(crate) async fn connect(server_name: String) -> Result<qconn::Connected> {
    let tls_name = qresolve::split_host_port(&server_name).0.to_owned();
    let client = qtls::TlsClient::new(qtls::ClientTlsConfig {
        provider: Arc::new(qtls::default_provider()),
        alpn: vec![h3x::ALPN.to_vec()],
        local: None,
        resumption: qtls::ClientResumptionConfig::Disabled,
        limits: Default::default(),
    })
    .map_err(|source| Error::TlsConfig {
        source: Arc::new(source),
    })?;
    let odcid = ConnectionId::random_gen(8);
    let initial_keys = client
        .initial_keys(qtls::QuicVersion::V1, odcid.as_ref())
        .map_err(|error| internal_error(error.to_string()))?;
    let reliable_frames = ArcReliableFrames::with_capacity(0);
    let (inbox, received) = channel::new();
    let router_registry =
        QuicRouter::global().registry_on_issuing_scid(inbox, reliable_frames.clone());
    let scid = router_registry.gen_unique_cid();
    let mut parameters = qbase::param::handy::client_parameters();
    parameters
        .set(ParameterId::InitialSourceConnectionId, scid)
        .map_err(|error| internal_error(error.to_string()))?;
    let tls = TlsContext::client(
        &client,
        tls_name
            .clone()
            .try_into()
            .map_err(|error| internal_error(format!("invalid server name: {error}")))?,
        &parameters,
    )?;
    let cid_registry = CidRegistry::new(
        Role::Client,
        odcid,
        ArcLocalCids::new(scid, router_registry),
        ArcRemoteCids::new(
            parameters.get::<u64>(ParameterId::ActiveConnectionIdLimit),
            reliable_frames.clone(),
        ),
    );
    let phase = ArcConnPhase::initial(InitialPhase::new(
        (scid, odcid),
        initial_keys,
        reliable_frames,
        cid_registry,
    ));
    let idle = ArcConnIdle::new(
        parameters.get::<Duration>(ParameterId::MaxIdleTimeout),
        Duration::ZERO,
        DEFAULT_HEARTBEAT_INTERVAL,
    );
    let paths = Paths::new(Role::Client, phase, idle);
    let token = ArcTokenRegistry::with_sink(tls_name, Arc::new(NoopTokenRegistry));
    let (deliver, connected) = oneshot::channel();

    // The existing client lifecycle owns resolution, TLS validation and path discovery.
    let tick = qconn::recv::tick(paths.clone());
    let growing = qconn::client_growing(
        server_name,
        parameters,
        paths,
        received,
        tls,
        token,
        move |result| {
            if let Err(Ok((_, _, connection))) = deliver.send(result) {
                connection.close(0u32.into(), "anonymous connection request cancelled");
            }
        },
    );
    tokio::spawn(async move { tokio::join!(growing, tick).0 });
    connected
        .await
        .map_err(|error| internal_error(error.to_string()))?
        .map_err(Error::from)
}

fn internal_error(reason: String) -> qconn::Error {
    QuicError::with_default_fty(ErrorKind::Internal, reason).into()
}
