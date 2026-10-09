#[path = "support/network.rs"]
mod network;

use std::{
    convert::Infallible,
    future::{Ready, ready},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use dhttp::{Body, DhttpNetwork, Endpoint, Error, Scope};
use http_body_util::Empty;
use tower_service::Service;

#[derive(Clone)]
struct EmptyApp;

impl Service<http::Request<Body>> for EmptyApp {
    type Response = http::Response<Empty<Bytes>>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Request<Body>) -> Self::Future {
        ready(Ok(http::Response::new(Empty::new())))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn listener_registers_service_and_releases_it_on_exit() {
    let root = std::env::temp_dir().join(format!("dhttp-listener-{}", std::process::id()));
    let ssl = root.join("test").join("ssl");
    std::fs::create_dir_all(&ssl).unwrap();
    let generated = rcgen::generate_simple_self_signed(vec!["test.dhttp.net".to_owned()]).unwrap();
    std::fs::write(ssl.join("fullchain.crt"), generated.cert.pem()).unwrap();
    std::fs::write(
        ssl.join("privkey.pem"),
        generated.signing_key.serialize_pem(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssl.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
    }
    std::fs::write(ssl.join("ocsp.der"), b"test-ocsp").unwrap();
    let other_ssl = root.join("other").join("ssl");
    std::fs::create_dir_all(&other_ssl).unwrap();
    let other_cert =
        rcgen::generate_simple_self_signed(vec!["other.dhttp.net".to_owned()]).unwrap();
    std::fs::write(other_ssl.join("fullchain.crt"), other_cert.cert.pem()).unwrap();
    std::fs::write(
        other_ssl.join("privkey.pem"),
        other_cert.signing_key.serialize_pem(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            other_ssl.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
    }
    std::fs::write(other_ssl.join("ocsp.der"), b"other-ocsp").unwrap();
    // This test binary has one test and sets the home before starting network tasks.
    unsafe { std::env::set_var("DHTTP_HOME", &root) };

    let endpoint = Endpoint::load("TEST").await.unwrap();
    assert_eq!(endpoint.name(), "test.dhttp.net");
    assert!(matches!(
        Endpoint::load("").await,
        Err(Error::InvalidName { .. })
    ));
    assert!(matches!(
        Endpoint::load("missing").await,
        Err(Error::Home { .. })
    ));
    DhttpNetwork::init().await.unwrap();
    let endpoints = network::loopback_endpoints();
    assert!(!endpoints.is_empty());
    let unpolled = endpoint
        .listen(Scope::Loopback.into(), EmptyApp)
        .await
        .unwrap();
    assert!(
        qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_some()
    );
    drop(unpolled);
    assert!(
        qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_none()
    );
    let listening = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            endpoint
                .listen(Scope::Loopback.into(), EmptyApp)
                .await
                .unwrap()
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if qconn::ServerRegistry::global()
                .get(endpoint.name())
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let other = Endpoint::load("other").await.unwrap();
    let other_listening = tokio::spawn({
        let other = other.clone();
        async move {
            other
                .listen(Scope::Internal | Scope::External, EmptyApp)
                .await
                .unwrap()
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if qconn::ServerRegistry::global().get(other.name()).is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let first = qconn::ServerRegistry::global()
        .get(endpoint.name())
        .unwrap();
    let second = qconn::ServerRegistry::global().get(other.name()).unwrap();
    // The new QUIC callback only delivers authenticated connections. Rejecting
    // an unsupported negotiated ALPN at the H3 boundary must still be local to
    // that connection and preserve the listener registration.
    let parameters = qbase::param::ArcParameters::new(
        qbase::role::Role::Server,
        std::sync::Arc::new(qbase::param::ClientParameters::default()),
        std::sync::Arc::new(qbase::param::ServerParameters::default()),
    );
    let streams = qconn::DataStreams::new(
        parameters,
        Box::new(qbase::sid::handy::DemandConcurrency),
        qconn::ArcReliableFrames::with_capacity(0),
        None,
    );
    let connection = qconn::ArcConnection::new(
        Bytes::from_static(b"h2"),
        streams,
        qtransport::terminate::ArcTerminator::no_error(),
    );
    (first.accept_cb)((None, endpoint.local_authority().unwrap(), connection));
    tokio::task::yield_now().await;
    assert!(
        !listening.is_finished(),
        "a rejected H3 setup must not stop the listener"
    );
    assert!(std::sync::Arc::ptr_eq(
        &first,
        &qconn::ServerRegistry::global()
            .get(endpoint.name())
            .unwrap()
    ));
    assert!(first.scopes.contains(Scope::Loopback));
    assert!(!first.scopes.contains(Scope::External));
    assert!(second.scopes.contains(Scope::External));
    assert!(second.scopes.contains(Scope::Internal));
    assert!(!second.scopes.contains(Scope::Loopback));

    assert!(matches!(
        endpoint.listen(Scope::External.into(), EmptyApp).await,
        Err(Error::AlreadyListening)
    ));
    let separate = Endpoint::load("test").await.unwrap();
    assert!(matches!(
        separate.listen(Scope::External.into(), EmptyApp).await,
        Err(Error::AlreadyListening)
    ));

    listening.abort();
    let _ = listening.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if qconn::ServerRegistry::global()
                .get(endpoint.name())
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    other_listening.abort();
    let _ = other_listening.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while qconn::ServerRegistry::global().get(other.name()).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        network::loopback_endpoints(),
        endpoints,
        "listener cleanup must preserve sockets used by outgoing connections"
    );
    assert!(!qprotocol::Dock::global().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
