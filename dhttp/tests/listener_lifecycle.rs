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
async fn listener_registration_cleans_up_on_cancel() {
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

    DhttpNetwork::init().await.unwrap();
    assert!(qprotocol::Dock::global().is_empty());
    let endpoint = Endpoint::load("test").await.unwrap();
    let listening = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.listen(Scope::Loopback.into(), EmptyApp).await }
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
    // Device binding needs host socket permission, which some test sandboxes deny.
    if std::env::var_os("DHTTP_TEST_SOCKET_BIND").is_some() {
        tokio::time::timeout(Duration::from_secs(2), async {
            while qprotocol::Dock::global().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server scope should create a network binding");
    }
    let other = Endpoint::load("other").await.unwrap();
    let other_listening = tokio::spawn({
        let other = other.clone();
        async move {
            other
                .listen(Scope::Internal | Scope::External, EmptyApp)
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
    (first.accept_cb)(Err(qbase::error::QuicError::with_default_fty(
        qbase::error::ErrorKind::Internal,
        "test rejected handshake",
    )
    .into()));
    tokio::task::yield_now().await;
    assert!(
        !listening.is_finished(),
        "a bad handshake must not stop the listener"
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
    let listening_again =
        tokio::spawn(async move { separate.listen(Scope::Loopback.into(), EmptyApp).await });
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
    // Stop withdraws admission synchronously; wait for the old supervisor to
    // finish before registering the same name again.
    endpoint.stop_listening().unwrap();
    assert!(
        qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_none()
    );
    assert!(listening_again.await.unwrap().is_ok());
    let newest = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.listen(Scope::Loopback.into(), EmptyApp).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A separately loaded handle stops the same listener without closing the identity.
    let same_name = Endpoint::load("TEST").await.unwrap();
    same_name.stop_listening().unwrap();
    assert!(newest.await.unwrap().is_ok());
    assert!(
        qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_none()
    );
    assert!(qconn::ServerRegistry::global().get(other.name()).is_some());
    let reopened = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.listen(Scope::Loopback.into(), EmptyApp).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while qconn::ServerRegistry::global()
            .get(endpoint.name())
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    same_name.stop_listening().unwrap();
    assert!(reopened.await.unwrap().is_ok());
    other.stop_listening().unwrap();
    assert!(qconn::ServerRegistry::global().get(other.name()).is_none());
    assert!(other_listening.await.unwrap().is_ok());
    assert!(qprotocol::Dock::global().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
