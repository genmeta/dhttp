//! Real UDP/TLS coverage; run explicitly on hosts with OpenSSL and socket permission.
use std::{
    fmt, fs,
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
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct PeerResolver(EndpointAddr, Arc<AtomicUsize>);

impl fmt::Display for PeerResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("local QUIC integration peer")
    }
}

impl Resolve for PeerResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            self.1.fetch_add(1, Ordering::SeqCst);
            assert!(matches!(name, "server.dhttp.net" | "wrong.dhttp.net"));
            assert!(family.is_none());
            Ok(futures::stream::iter([(Source::System, self.0)]).boxed())
        }
        .boxed()
    }
}

#[path = "support/credentials.rs"]
mod credentials;

#[tokio::test]
#[ignore = "requires OpenSSL and local UDP socket permission"]
async fn injected_resolver_drives_authenticated_http3_over_udp() {
    let root = std::env::temp_dir().join(format!("dhttp-quic-roundtrip-{}", std::process::id()));
    let _home = scopeguard::guard(root.clone(), |root| {
        let _ = fs::remove_dir_all(root);
    });
    credentials::generate(
        &root,
        &[
            ("server", "server.dhttp.net"),
            ("client", "client.dhttp.net"),
            ("wrong", "server.dhttp.net"),
        ],
    );
    // This binary has one test; set the home before spawning network tasks.
    unsafe { std::env::set_var("DHTTP_HOME", &root) };

    // Give the in-process server a distinct UDP address so discovery creates a real path.
    let peer = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let address = EndpointAddr::direct(peer.local_addr().unwrap());
    Dock::global().add(peer.clone()).unwrap().unwrap();
    let _peer = scopeguard::guard(peer, |peer| {
        Dock::global().remove(&peer);
    });
    DhttpNetwork::init().await.unwrap();
    // Sources can be registered independently of network startup.
    let resolutions = Arc::new(AtomicUsize::new(0));
    dhttp::resolve::Resolver::add(Arc::new(PeerResolver(address, resolutions.clone())));
    let ca = fs::read(root.join("ca.crt")).unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    assert!(!Dock::global().is_empty());
    assert!(
        qconn::ServerRegistry::global()
            .get("client.dhttp.net")
            .is_none()
    );

    let server = Endpoint::load("SERVER").await.unwrap();
    assert_eq!(server.name(), Some("server.dhttp.net"));
    // Listening must use the credentials retained by Endpoint::load.
    fs::remove_dir_all(root.join("server")).unwrap();
    let listening = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .listen(
                    Scope::Loopback.into(),
                    tower::service_fn(|request: http::Request<Body>| async move {
                        let handshake = request.extensions().get::<HandshakeSummary>().unwrap();
                        assert_eq!(handshake.alpn.as_deref(), Some(b"h3".as_slice()));
                        assert_eq!(handshake.local.as_ref().unwrap().name(), "server.dhttp.net");
                        if request.uri().path() == "/anonymous" {
                            assert!(handshake.remote.is_none());
                        } else {
                            assert_eq!(
                                handshake.remote.as_ref().unwrap().name(),
                                "client.dhttp.net"
                            );
                        }
                        let bytes = request.into_body().collect().await?.to_bytes();
                        Ok::<_, dhttp::BoxError>(http::Response::new(Full::new(bytes)))
                    }),
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while qconn::ServerRegistry::global()
            .get("server.dhttp.net")
            .is_none()
        {
            assert!(
                !listening.is_finished(),
                "listener exited before registration"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let client = Endpoint::load("client").await.unwrap();
    let same_name = Endpoint::load("client").await.unwrap();
    // A fresh connection and later listeners must also use the loaded credentials.
    fs::remove_dir_all(root.join("client")).unwrap();
    assert!(matches!(
        Endpoint::load("client").await,
        Err(dhttp::Error::Home { .. })
    ));
    let payload = Bytes::from(vec![0x5a; 96 * 1024]);
    for same_name in [&client, &same_name] {
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let (mut request, response) = same_name
                .post("https://server~/echo".parse().unwrap())
                .body(dhttp::WndBuf::with_initial(64 * 1024, payload.clone()))
                .await?;
            request.shutdown().await?;
            response.await
        })
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
        let echoed = tokio::time::timeout(Duration::from_secs(10), response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert_eq!(echoed, payload);
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "same-name handles must reuse the connection"
    );
    let client_listener = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .listen(
                    Scope::Loopback.into(),
                    tower::service_fn(|request: http::Request<Body>| async move {
                        let handshake = request.extensions().get::<HandshakeSummary>().unwrap();
                        assert_eq!(handshake.alpn.as_deref(), Some(b"h3".as_slice()));
                        assert_eq!(handshake.local.as_ref().unwrap().name(), "client.dhttp.net");
                        assert_eq!(
                            handshake.remote.as_ref().unwrap().name(),
                            "server.dhttp.net"
                        );
                        Ok::<_, dhttp::BoxError>(http::Response::new(Full::new(
                            Bytes::from_static(b"reverse"),
                        )))
                    }),
                )
                .await
        }
    });
    wait_listener("client.dhttp.net").await;
    // Anonymous requests work without either local identity directory.
    for request in [
        Endpoint::new(None)
            .post("https://server~/anonymous".parse().unwrap())
            .write(b"anonymous"),
        dhttp::Request::new(
            http::Request::builder()
                .method("POST")
                .uri("https://server~/anonymous")
                .body(dhttp::WndBuf::with_initial(
                    64 * 1024,
                    Bytes::from_static(b"anonymous"),
                ))
                .unwrap(),
        ),
    ] {
        let response = tokio::time::timeout(Duration::from_secs(3), async {
            let (mut request, response) = request.await?;
            request.shutdown().await?;
            response.await
        })
        .await
        .unwrap()
        .unwrap();
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
            "anonymous"
        );
    }
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "anonymous requests need a distinct reusable connection"
    );
    let reverse = tokio::time::timeout(
        Duration::from_secs(3),
        server.get("https://client~/reverse".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        reverse.into_body().collect().await.unwrap().to_bytes(),
        "reverse"
    );

    listening.abort();
    let _ = listening.await;
    let rejected = tokio::time::timeout(
        Duration::from_secs(3),
        client.get("https://server~/stopped".parse().unwrap()),
    )
    .await
    .expect("a stopped listener must reject the stream promptly");
    assert!(rejected.is_err());
    // The server's outgoing requests still use this connection after its listener stops.
    let reverse = tokio::time::timeout(
        Duration::from_secs(3),
        server.get("https://client~/still-open".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        reverse.into_body().collect().await.unwrap().to_bytes(),
        "reverse"
    );
    let replacement = tokio::spawn(async move {
        server
            .listen(
                Scope::Loopback.into(),
                tower::service_fn(|_: http::Request<Body>| async {
                    Ok::<_, dhttp::BoxError>(http::Response::new(Full::new(Bytes::from_static(
                        b"replacement",
                    ))))
                }),
            )
            .await
    });
    wait_listener("server.dhttp.net").await;
    let resumed = tokio::time::timeout(
        Duration::from_secs(3),
        client.get("https://server~/resumed".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        resumed.into_body().collect().await.unwrap().to_bytes(),
        "replacement"
    );
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "bidirectional requests and listener replacement must reuse the named connection"
    );
    // An anonymous client still rejects a peer without credentials for the target name.
    let wrong = Endpoint::load("wrong").await.unwrap();
    let wrong_listener = tokio::spawn(async move {
        wrong
            .listen(
                Scope::Loopback.into(),
                tower::service_fn(|_: http::Request<Body>| async {
                    Ok::<_, dhttp::BoxError>(http::Response::new(Body::default()))
                }),
            )
            .await
    });
    let _wrong = scopeguard::guard(wrong_listener, |task| task.abort());
    wait_listener("wrong.dhttp.net").await;
    let wrong_peer = tokio::time::timeout(
        Duration::from_secs(3),
        Endpoint::new(None).get("https://wrong~/anonymous".parse().unwrap()),
    )
    .await
    .expect("an invalid server certificate must fail promptly");
    assert!(wrong_peer.is_err());
    replacement.abort();
    let _ = replacement.await;
    client_listener.abort();
    let _ = client_listener.await;
    assert!(
        qconn::ServerRegistry::global()
            .get("server.dhttp.net")
            .is_none()
    );
    assert!(!Dock::global().is_empty());
}

async fn wait_listener(name: &str) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while qconn::ServerRegistry::global().get(name).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
