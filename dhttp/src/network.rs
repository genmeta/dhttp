//! Process-wide network initialization, HTTP/3 connection pool and service registry.
mod connection;
mod interfaces;

use crate::{Body, BoxError, Endpoint, Error, Result, transport::QuicTransport};
use connection::{ConnectionKey, H3, connect, serve_connection};
use qconn::Scopes;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) type BoxService =
    tower::util::BoxCloneService<http::Request<Body>, http::Response<Body>, BoxError>;

static NETWORK: tokio::sync::OnceCell<DhttpNetwork> = tokio::sync::OnceCell::const_new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DhttpNetwork {
    interfaces: interfaces::Interfaces,
    listeners: Mutex<HashMap<Arc<str>, BoxService>>,
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
}

impl DhttpNetwork {
    /// Prepare all available interfaces and watch for subsequent interface changes.
    /// Repeated or concurrent calls return the same process-wide network. Individual
    /// binding failures are logged and retried on interface changes and periodic checks.
    /// NAT classification runs once per binding in the maintenance task; subsequent
    /// STUN binding heartbeats keep mappings alive. Initialization does not wait for STUN.
    /// The Tokio runtime must remain alive for the lifetime of the network.
    pub async fn init() -> Result<&'static Self> {
        NETWORK
            .get_or_try_init(|| async {
                crate::trust::initialize()?;
                let interfaces = interfaces::Interfaces::init().await?;
                Ok::<_, Error>(Self {
                    interfaces,
                    listeners: Mutex::new(HashMap::new()),
                    pool: h3x::Pool::new(connect),
                })
            })
            .await
    }

    pub fn global() -> Result<&'static Self> {
        NETWORK.get().ok_or(Error::NetworkNotInitialized)
    }

    /// Refresh network resources after device wake or application foregrounding.
    /// No preceding suspend call is required. State changes are serialized with interface polling.
    /// Returns after refreshing the interface watcher and scanning current bindings,
    /// preserving live sockets and their ports, and scheduling immediate STUN refreshes.
    /// Individual binding failures are logged and retried by periodic maintenance.
    /// Does not wait for STUN or guarantee Internet reachability, reconnect terminated
    /// connections, or replay HTTP requests. The original Tokio runtime must remain alive.
    pub async fn resume(&self) -> Result<()> {
        self.interfaces.resume().await
    }

    pub(crate) async fn get_connection(
        &'static self,
        local: Option<Endpoint>,
        remote: Arc<str>,
    ) -> Result<H3> {
        let key = ConnectionKey::Outgoing { local, remote };
        let result = tokio::time::timeout(CONNECT_TIMEOUT, self.pool.get(&key))
            .await
            .map_err(std::io::Error::other)?;
        match &result {
            Ok(h3) => tracing::trace!(
                local = ?h3.transport().handshake.local.as_ref().map(qtls::LocalAuthority::name),
                remote = ?h3.transport().handshake.remote.as_ref().map(qtls::RemoteAuthority::name),
                paths = ?h3.transport().connection.validated_paths(),
                "HTTP/3 connection ready for outgoing request"
            ),
            Err(error) => tracing::trace!(%error, "HTTP/3 connection acquisition failed"),
        }
        result
    }

    pub(crate) async fn listen(
        &'static self,
        endpoint: &Endpoint,
        scopes: Scopes,
        service: BoxService,
    ) -> Result<crate::ListenFuture> {
        let quic = &endpoint.quic;
        let name: Arc<str> = Arc::from(quic.identity.name());
        {
            let mut listeners = self.listeners.lock().unwrap();
            if listeners.contains_key(&name) {
                return Err(Error::AlreadyListening);
            }
            if qconn::ServerRegistry::global().get(&name).is_some() {
                return Err(Error::NameInUse {
                    name: name.to_string(),
                });
            }
            quic.listen(scopes, {
                let name = name.clone();
                move |result| {
                    let (remote, local, connection) = match result {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::debug!(endpoint = %name, %error, "incoming connection rejected");
                            return;
                        }
                    };
                    tracing::trace!(
                        local = %local.name(),
                        remote = ?remote.as_ref().map(qtls::RemoteAuthority::name),
                        paths = ?connection.validated_paths(),
                        "incoming QUIC handshake completed"
                    );
                    let connection = QuicTransport::new(
                        connection, Some(local), remote, h3x::Role::Server,
                    ).and_then(|transport| {
                        H3::new(transport, h3x::Settings::default()).map_err(Error::from)
                    });
                    let h3 = match connection {
                        Ok(h3) => h3,
                        Err(error) => {
                            tracing::debug!(endpoint = %name, %error, "HTTP/3 setup failed");
                            return;
                        }
                    };
                    let key = ConnectionKey::Incoming {
                        local: name.clone(),
                        remote: h3.transport().handshake.remote.as_ref()
                            .map(|remote| Arc::from(remote.name())),
                    };
                    let _ = self.pool.insert(key.clone(), h3.clone());
                    tokio::spawn(serve_connection(self, key, h3));
                }
            })?;
            listeners.insert(name.clone(), service);
        }
        let cleanup = scopeguard::guard(name.clone(), |name| {
            let mut listeners = self.listeners.lock().unwrap();
            listeners.remove(&name);
            qconn::ServerRegistry::global().remove(&name);
        });
        Ok(Box::pin(async move {
            let _cleanup = cleanup;
            std::future::pending::<()>().await;
        }))
    }
}

impl Endpoint {
    /// Rebuild immutable credentials and replace an existing TLS registration.
    /// The application callback, listener lifetime, scopes and connection pool remain owned by Network.
    /// Certificate/key rotation requires application restart; this operation renews only the staple.
    pub async fn reload(&self) -> Result<Self> {
        self.replace_staple(Self::load(self.name()).await?)
    }

    /// Reload the staple from an explicit profile without changing DHTTP_HOME.
    /// The profile must retain this endpoint's name and certificate chain.
    pub async fn reload_from(&self, path: impl AsRef<std::path::Path>) -> Result<Self> {
        self.replace_staple(Self::load_from(path).await?)
    }

    fn replace_staple(&self, mut replacement: Self) -> Result<Self> {
        if replacement.name() != self.name() {
            return Err(Error::InvalidName {
                name: replacement.name().to_owned(),
            });
        }
        if replacement.quic.identity.cert_chain() != self.quic.identity.cert_chain() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "certificate chain changed; restart required",
            )
            .into());
        }
        qtls::validate_ocsp(
            replacement.quic.identity.ocsp(),
            replacement.quic.identity.cert_chain(),
            qtls::UnixTime::now(),
        )
        .map_err(std::io::Error::other)?;
        let network = DhttpNetwork::global()?;
        let listeners = network
            .listeners
            .lock()
            .map_err(|_| std::io::Error::other("listener registry poisoned"))?;
        if listeners.contains_key(self.name()) {
            let registered = qconn::ServerRegistry::global()
                .get(self.name())
                .ok_or_else(|| std::io::Error::other("listener TLS registration disappeared"))?;
            let quic = Arc::get_mut(&mut replacement.quic)
                .ok_or_else(|| std::io::Error::other("replacement endpoint unexpectedly shared"))?;
            quic.server_parameters = registered.server_parameters.clone();
            quic.listen(registered.scopes, move |result| {
                (registered.accept_cb)(result)
            })
            .map_err(std::io::Error::other)?;
        }
        Ok(replacement)
    }
}
