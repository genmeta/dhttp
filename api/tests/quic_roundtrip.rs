//! SDK bridge acceptance over real UDP/TLS/H3; isolated process and temporary profiles.
use bytes::Bytes;
use dhttp::resolve::{EndpointAddr, Family, Resolve, ResolveFuture, Source};
use dhttp_api::{
    Client, Error, ErrorCode, RequestOptions, ServerRequest, ServerResponse, upload_channel,
};
use futures::{FutureExt, StreamExt};
use http::{HeaderMap, Method};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use qprotocol::{Dock, UdpSocket};
use std::{fmt, fs, sync::Arc, time::Duration};

#[path = "../../dhttp/tests/support/credentials.rs"]
mod credentials;

#[derive(Debug)]
struct Resolver(EndpointAddr);
impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SDK local test resolver")
    }
}
impl Resolve for Resolver {
    fn lookup<'a>(&'a self, name: &'a str, _: &'a str, _: Option<Family>) -> ResolveFuture<'a> {
        async move {
            assert!(matches!(name, "server.dhttp.net" | "alice.dhttp.net"));
            Ok(futures::stream::iter([(Source::System, self.0)]).boxed())
        }
        .boxed()
    }
}

fn get(path: &str) -> http::Request<Option<dhttp_api::UploadBody>> {
    http::Request::builder()
        .uri(format!("https://server~/{path}"))
        .body(None)
        .unwrap()
}

async fn read_body(response: &dhttp_api::ClientResponse) -> dhttp_api::Result<Bytes> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.body().next().await? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(bytes))
}

async fn handler(request: ServerRequest) -> dhttp_api::Result<ServerResponse> {
    let handshake = request
        .extensions()
        .get::<dhttp::HandshakeSummary>()
        .unwrap();
    assert_eq!(handshake.local.as_ref().unwrap().name(), "server.dhttp.net");
    match request.uri().path() {
        "/echo" => {
            assert_eq!(handshake.remote.as_ref().unwrap().name(), "alice.dhttp.net");
            assert_eq!(request.headers().get_all("x-repeat").iter().count(), 2);
            // Return headers before reading any upload bytes. The standard Body
            // keeps reading the request and writing the response concurrently.
            let body = StreamBody::new(async_stream::try_stream! {
                while let Some(bytes) = request.body().next().await? { yield Frame::data(bytes); }
                let trailers = request.body().trailers().await?;
                assert_eq!(trailers.get_all("x-upload-end").iter().count(), 2);
                yield Frame::trailers(trailers);
            });
            let body =
                BodyExt::map_err(body, |error: Error| -> dhttp::BoxError { Box::new(error) })
                    .boxed_unsync();
            Ok(http::Response::builder()
                .header("x-repeat", "one")
                .header("x-repeat", "two")
                .body(body)
                .unwrap())
        }
        "/error" => Err(Error::producer(std::io::Error::other(
            "private exception detail",
        ))),
        "/hang" => futures::future::pending().await,
        "/pending-body" => {
            let body = StreamBody::new(futures::stream::pending::<
                std::result::Result<Frame<Bytes>, dhttp::BoxError>,
            >());
            Ok(http::Response::new(body.boxed_unsync()))
        }
        "/anonymous" => {
            assert!(handshake.remote.is_none());
            Ok(http::Response::new(
                Full::new(Bytes::from_static(b"anonymous"))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            ))
        }
        _ => Ok(http::Response::new(
            Full::new(Bytes::from_static(b"ok"))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )),
    }
}

#[tokio::test]
#[ignore = "requires OpenSSL and local UDP socket permission"]
async fn shared_bridge_streams_and_reclaims_its_own_resources_over_quic() {
    tokio::time::timeout(Duration::from_secs(30), acceptance())
        .await
        .unwrap();
}

async fn acceptance() {
    let root = std::env::temp_dir().join(format!("dhttp-sdk-roundtrip-{}", std::process::id()));
    let _cleanup = scopeguard::guard(root.clone(), |root| {
        let _ = fs::remove_dir_all(root);
    });
    credentials::generate(
        &root,
        &[
            ("server", "server.dhttp.net"),
            ("alice", "alice.dhttp.net"),
            ("bob", "bob.dhttp.net"),
        ],
    );
    let original_home = std::env::var_os("DHTTP_HOME");
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let address = EndpointAddr::direct(socket.local_addr().unwrap());
    Dock::global().add(socket.clone()).unwrap().unwrap();
    let _socket = scopeguard::guard(socket, |socket| {
        Dock::global().remove(&socket);
    });
    dhttp::resolve::Resolver::add(Arc::new(Resolver(address)));
    dhttp_api::init().await.unwrap();
    let ca = fs::read(root.join("ca.crt")).unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    let server = Client::load_from(root.join("server")).await.unwrap();
    let alice = Client::load_from(root.join("alice")).await.unwrap();
    let bob = Client::load_from(root.join("bob")).await.unwrap();
    assert_eq!(std::env::var_os("DHTTP_HOME"), original_home);
    assert_eq!(alice.name().await.as_deref(), Some("alice.dhttp.net"));
    alice.reload().await.unwrap();
    let listener = server
        .listen(dhttp::Scope::Loopback.into(), handler)
        .await
        .unwrap();
    server.reload().await.unwrap();
    let second = server.listen(dhttp::Scope::Loopback.into(), handler).await;
    assert!(matches!(second, Err(error) if error.code == ErrorCode::AlreadyListening));
    // A failed explicit-path reload retains the previous signing capability.
    let original = alice.local_authority().await.unwrap().unwrap();
    let ocsp_path = root.join("alice/ssl/ocsp.der");
    let ocsp = fs::read(&ocsp_path).unwrap();
    fs::write(&ocsp_path, b"invalid OCSP").unwrap();
    assert!(alice.reload().await.is_err());
    assert_eq!(
        alice.local_authority().await.unwrap().unwrap().ocsp(),
        original.ocsp()
    );
    fs::write(&ocsp_path, ocsp).unwrap();
    let core_alice = dhttp::Endpoint::load_from(root.join("alice"))
        .await
        .unwrap();
    assert!(core_alice.reload_from(root.join("bob")).await.is_err());
    assert!(
        dhttp::Endpoint::load_from(root.join("*.alice"))
            .await
            .is_err()
    );
    let anonymous = Client::anonymous();
    let response = anonymous
        .request(get("anonymous"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        response
            .extensions()
            .get::<dhttp::RemoteAuthority>()
            .unwrap()
            .name(),
        "server.dhttp.net"
    );
    assert_eq!(read_body(&response).await.unwrap(), "anonymous");
    assert!(response.body().trailers().await.unwrap().is_empty());

    // Bidirectional requests reuse authenticated core connections.
    let reverse_listener = alice
        .listen(
            dhttp::Scope::Loopback.into(),
            |request: ServerRequest| async move {
                assert_eq!(
                    request
                        .extensions()
                        .get::<dhttp::HandshakeSummary>()
                        .unwrap()
                        .remote
                        .as_ref()
                        .unwrap()
                        .name(),
                    "server.dhttp.net"
                );
                Ok(http::Response::new(
                    Full::new(Bytes::from_static(b"reverse"))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                ))
            },
        )
        .await
        .unwrap();

    let (writer, body) = upload_channel();
    let message = http::Request::builder()
        .method(Method::POST)
        .uri("https://server~/echo")
        .header("x-repeat", "one")
        .header("x-repeat", "two")
        .body(Some(body))
        .unwrap();
    let response = alice
        .request(message, RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    // No producer bytes have been sent yet: response headers really arrive early.
    assert_eq!(response.headers().get_all("x-repeat").iter().count(), 2);
    let payload = vec![0x5a; 512 * 1024];
    let (sent, received) = tokio::join!(
        async {
            writer.send(&payload).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.append("x-upload-end", "one".parse().unwrap());
            trailers.append("x-upload-end", "two".parse().unwrap());
            writer.finish(trailers).await.unwrap();
        },
        read_body(&response)
    );
    assert_eq!(sent, ());
    assert_eq!(received.unwrap().as_ref(), payload.as_slice());
    assert_eq!(
        response
            .body()
            .trailers()
            .await
            .unwrap()
            .get_all("x-upload-end")
            .iter()
            .count(),
        2
    );
    let reverse = server
        .request(
            http::Request::builder()
                .uri("https://alice~/reverse")
                .body(None)
                .unwrap(),
            RequestOptions::default(),
        )
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(read_body(&reverse).await.unwrap(), "reverse");

    // A pin is checked on an already pooled connection before sending anything.
    let options = RequestOptions {
        expected_remote_owner_hash: Some(
            dhttp_home::certificate::OwnerHash::try_from("f".repeat(64).as_str()).unwrap(),
        ),
        ..Default::default()
    };
    let result = alice.request(get("ok"), options).await.unwrap().await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::RemoteIdentityChanged));
    let response = alice
        .request(get("error"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    assert!(read_body(&response).await.unwrap().is_empty());

    // Cancellation before and after headers, and a deadline, leave the pool usable.
    let pending = alice
        .request(get("hang"), RequestOptions::default())
        .await
        .unwrap();
    pending.cancellation().cancel();
    assert!(matches!(pending.await, Err(error) if error.code == ErrorCode::Cancelled));
    let response = alice
        .request(get("pending-body"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    response.body().cancel();
    assert_eq!(
        response.body().next().await.unwrap_err().code,
        ErrorCode::Cancelled
    );
    let options = RequestOptions {
        timeout: Some(Duration::from_millis(50)),
        ..Default::default()
    };
    let result = alice.request(get("hang"), options).await.unwrap().await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::DeadlineExceeded));

    let (writer, body) = upload_channel();
    let mut message = get("pending-body");
    *message.body_mut() = Some(body);
    let response = alice
        .request(message, RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    writer.fail(Error::producer(std::io::Error::other("producer exploded")));
    assert_eq!(
        response.body().next().await.unwrap_err().code,
        ErrorCode::Producer
    );
    assert_eq!(
        response.body().trailers().await.unwrap_err().code,
        ErrorCode::Producer
    );

    // Independently loaded same-name handles have independent SDK ownership.
    let other_alice = Client::load_from(root.join("alice")).await.unwrap();

    let response = alice
        .request(get("pending-body"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    alice.close().await;
    assert_eq!(
        response.body().next().await.unwrap_err().code,
        ErrorCode::Closed
    );
    assert!(
        matches!(alice.request(get("ok"), RequestOptions::default()).await, Err(error) if error.code == ErrorCode::Closed)
    );
    reverse_listener.close().await;
    let response = other_alice
        .request(get("ok"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(read_body(&response).await.unwrap(), "ok");
    other_alice.close().await;
    let response = bob
        .request(get("ok"), RequestOptions::default())
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(read_body(&response).await.unwrap(), "ok");
    // Listener close cancels a stalled handler and releases its name for re-listen.
    listener.close().await;
    listener.close().await;
    let listener = server
        .listen(dhttp::Scope::Loopback.into(), handler)
        .await
        .unwrap();
    listener.close().await;
    anonymous.close().await;
    bob.close().await;
    server.close().await;
}
