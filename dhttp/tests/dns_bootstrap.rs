//! Real H3 DNS bootstrap through an application-supplied global routing resolver.
use std::{
    fmt, fs, io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use dhttp::resolve::{EndpointAddr, Family, Resolve, ResolveFuture, Source};
use dhttp::{Body, DhttpNetwork, Endpoint, HandshakeSummary, RemoteAuthority, Scope};
use futures::{FutureExt, StreamExt};
use http_body_util::{BodyExt, Full};
use qprotocol::{Dock, UdpSocket};

#[path = "support/credentials.rs"]
mod credentials;

struct ApplicationResolver {
    client: Endpoint,
    origin: http::Uri,
    calls: Arc<AtomicUsize>,
    system_calls: Arc<AtomicUsize>,
}

impl fmt::Debug for ApplicationResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationResolver")
            .field("origin", &self.origin)
            .finish()
    }
}

impl fmt::Display for ApplicationResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H3 lookup through {}", self.origin)
    }
}

impl Resolve for ApplicationResolver {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            // The application routes bootstrap names before invoking its H3 DNS client.
            if !hostname.ends_with(dhttp_home::DHTTP_SUFFIX) {
                self.system_calls.fetch_add(1, Ordering::SeqCst);
                return dhttp::resolve::SystemResolver
                    .lookup(hostname, servname, family)
                    .await;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if hostname != "server.dhttp.net" {
                return Err(io::Error::other(
                    "bootstrap origin re-entered the injected resolver",
                ));
            }
            let response = self
                .client
                .get(self.origin.clone())
                .await
                .map_err(io::Error::other)?;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                response
                    .extensions()
                    .get::<RemoteAuthority>()
                    .unwrap()
                    .name(),
                "localhost"
            );
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(io::Error::other)?
                .to_bytes();
            let address = std::str::from_utf8(&body).unwrap().parse().unwrap();
            Ok(futures::stream::iter([(
                Source::H3 {
                    server: Arc::from(self.origin.authority().unwrap().as_str()),
                },
                EndpointAddr::direct(address),
            )])
            .boxed())
        }
        .boxed()
    }
}

fn endpoint(root: &Path, directory: &str, name: &str) -> Endpoint {
    let ssl = root.join(directory).join("ssl");
    let certs = fs::read(ssl.join("fullchain.crt")).unwrap();
    let key = fs::read(ssl.join("privkey.pem")).unwrap();
    let identity = qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        name,
        rustls_pemfile::certs(&mut certs.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        rustls_pemfile::private_key(&mut key.as_slice())
            .unwrap()
            .unwrap(),
        fs::read(ssl.join("ocsp.der")).unwrap(),
    )
    .unwrap();
    Endpoint::new(Some(identity))
}

#[tokio::test]
#[ignore = "requires OpenSSL and local UDP socket permission"]
async fn global_resolver_bootstraps_h3_lookup_and_keeps_origin_ports() {
    let root = std::env::temp_dir().join(format!("dhttp-dns-bootstrap-{}", std::process::id()));
    let _files = scopeguard::guard(root.clone(), |root| {
        let _ = fs::remove_dir_all(root);
    });
    credentials::generate(
        &root,
        &[
            ("origin", "localhost"),
            ("client", "client.dhttp.net"),
            ("server", "server.dhttp.net"),
        ],
    );
    DhttpNetwork::init().await.unwrap();
    let ca = fs::read(root.join("ca.crt")).unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();

    // Distinct actual sockets expose lost ports and keep the test off public networks.
    let sockets = (0..3)
        .map(|_| {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
            Dock::global().add(socket.clone()).unwrap().unwrap();
            socket
        })
        .collect::<Vec<_>>();
    let addresses = sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect::<Vec<_>>();
    let _sockets = scopeguard::guard(sockets, |sockets| {
        for socket in sockets {
            Dock::global().remove(&socket);
        }
    });
    let origin = endpoint(&root, "origin", "localhost");
    let server = endpoint(&root, "server", "server.dhttp.net");
    let client = endpoint(&root, "client", "client.dhttp.net");
    let peer = addresses[2].to_string();
    let origin_listener = tokio::spawn(async move {
        origin
            .listen(
                Scope::Loopback.into(),
                tower::service_fn(move |request: http::Request<Body>| {
                    let peer = peer.clone();
                    async move {
                        let handshake = request.extensions().get::<HandshakeSummary>().unwrap();
                        assert_eq!(handshake.local.as_ref().unwrap().name(), "localhost");
                        assert_eq!(
                            handshake.remote.as_ref().unwrap().name(),
                            "client.dhttp.net"
                        );
                        let body = if request.uri().path() == "/lookup" {
                            peer
                        } else {
                            request.uri().to_string()
                        };
                        Ok::<_, dhttp::BoxError>(http::Response::new(Full::new(Bytes::from(body))))
                    }
                }),
            )
            .await
    });
    let _origin = scopeguard::guard(origin_listener, |task| task.abort());
    let server_listener = tokio::spawn(async move {
        server
            .listen(
                Scope::Loopback.into(),
                tower::service_fn(|_: http::Request<Body>| async {
                    Ok::<_, dhttp::BoxError>(http::Response::new(Full::new(Bytes::from_static(
                        b"discovered",
                    ))))
                }),
            )
            .await
    });
    let _server = scopeguard::guard(server_listener, |task| task.abort());
    tokio::time::timeout(Duration::from_secs(3), async {
        while qconn::ServerRegistry::global().get("localhost").is_none()
            || qconn::ServerRegistry::global()
                .get("server.dhttp.net")
                .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let system_calls = Arc::new(AtomicUsize::new(0));
    dhttp::resolve::Resolver::add(Arc::new(ApplicationResolver {
        client: client.clone(),
        origin: format!("https://localhost:{}/lookup", addresses[0].port())
            .parse()
            .unwrap(),
        calls: calls.clone(),
        system_calls: system_calls.clone(),
    }));
    // The only injected resolver itself needs HTTP/3 to discover the target.
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.get("https://server~/resource".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<RemoteAuthority>()
            .unwrap()
            .name(),
        "server.dhttp.net"
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "discovered"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(system_calls.load(Ordering::SeqCst), 1);

    for address in &addresses[..2] {
        let uri = format!("https://localhost:{}/origin", address.port());
        let response =
            tokio::time::timeout(Duration::from_secs(5), client.get(uri.parse().unwrap()))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response
                .extensions()
                .get::<RemoteAuthority>()
                .unwrap()
                .name(),
            "localhost"
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            uri
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "ordinary origins use the injected resolver's system DNS branch"
    );
    assert_eq!(
        system_calls.load(Ordering::SeqCst),
        2,
        "same origin reuses its connection; a different port needs a separate lookup"
    );
}
