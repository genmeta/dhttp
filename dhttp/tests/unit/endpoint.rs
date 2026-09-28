//! Transport-independent tests: all HTTP/3 traffic stays inside Tokio duplex streams.
use super::messages::send_request;
use super::*;
use http_body_util::{Empty, Full};
use std::{sync::Mutex, time::Duration};
use tokio::io::AsyncReadExt;
#[path = "../support/transport.rs"]
mod support;

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("in-memory exchange must finish")
}
fn handshake(name: &str) -> Arc<qtls::HandshakeSummary> {
    let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let local = qtls::LocalAuthority::new(
        &qtls::default_provider(),
        Arc::from(name),
        vec![generated.cert.der().clone()],
        qtls::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
        vec![1],
    )
    .unwrap();
    Arc::new(qtls::HandshakeSummary {
        local: Some(local),
        remote: None,
        alpn: Some(Bytes::from_static(h3x::ALPN)),
    })
}
fn pending_body(dropped: tokio::sync::oneshot::Sender<()>) -> Body {
    let guard = scopeguard::guard(dropped, |sender| {
        let _ = sender.send(());
    });
    let stream = async_stream::stream! {
        let _guard = guard;
        std::future::pending::<()>().await;
        yield Ok::<_, BoxError>(Frame::data(Bytes::new()));
    };
    StreamBody::new(stream).boxed_unsync()
}
fn frames_body(data: &'static [u8]) -> Body {
    let mut trailers = http::HeaderMap::new();
    trailers.append("x-tag", http::HeaderValue::from_static("one"));
    trailers.append("x-tag", http::HeaderValue::from_static("two"));
    StreamBody::new(futures::stream::iter([
        Ok::<_, BoxError>(Frame::data(Bytes::from_static(data))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed_unsync()
}

#[tokio::test]
async fn inbound_body_transfers_bytes_without_copy_and_preserves_eof() {
    let native = h3x::ArcWndBuf::new(BODY_READ_CHUNK_BYTES);
    let data = Bytes::from_static(b"shared body bytes");
    native.write_bytes(data.clone()).await.unwrap();
    native.clone().shutdown().await.unwrap();

    let mut body = StreamBody::new(forward_inbound_body(
        native.clone(),
        h3x::Trailers::default(),
    ))
    .boxed_unsync();
    let received = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(received, data);
    assert_eq!(received.as_ptr(), data.as_ptr());
    assert!(body.frame().await.is_none());
    drop(body);
    assert!(
        native
            .read_chunk(BODY_READ_CHUNK_BYTES)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn dropping_unpolled_inbound_body_stops_native_reader() {
    let native = h3x::ArcWndBuf::new(BODY_READ_CHUNK_BYTES);
    drop(forward_inbound_body(
        native.clone(),
        h3x::Trailers::default(),
    ));
    assert!(native.read_chunk(BODY_READ_CHUNK_BYTES).await.is_err());
}

#[tokio::test]
async fn builder_works_without_network_and_body_replacement_drops_previous_producer() {
    let endpoint = Endpoint::load("ALICE").await.unwrap();
    assert_eq!(endpoint.name(), "alice.dhttp.net");
    let uri = "https://bob~/upload".parse().unwrap();
    let (dropped, observed) = tokio::sync::oneshot::channel();
    let request = endpoint
        .get(uri)
        .header(http::header::ACCEPT, http::HeaderValue::from_static("one"))
        .append_header(http::header::ACCEPT, http::HeaderValue::from_static("two"))
        .body(pending_body(dropped))
        .body(Empty::<Bytes>::new());
    bounded(observed).await.unwrap();
    assert_eq!(
        request
            .message
            .headers()
            .get_all(http::header::ACCEPT)
            .iter()
            .count(),
        2
    );
    assert_eq!(request.message.method(), http::Method::GET);
}

#[tokio::test]
async fn standard_request_and_response_preserve_data_and_duplicate_trailers() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let (seen, observed) = tokio::sync::oneshot::channel();
        let seen = Arc::new(Mutex::new(Some(seen)));
        let app = tower::service_fn(move |request: http::Request<Body>| {
            let seen = seen.lock().unwrap().take().unwrap();
            async move {
                assert!(
                    request
                        .extensions()
                        .get::<qtls::HandshakeSummary>()
                        .is_some()
                );
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "bob.dhttp.net:70000"
                );
                let collected = request.into_body().collect().await?;
                assert_eq!(
                    collected
                        .trailers()
                        .unwrap()
                        .get_all("x-tag")
                        .iter()
                        .count(),
                    2
                );
                assert_eq!(collected.to_bytes(), "upload");
                let _ = seen.send(());
                Ok::<_, BoxError>(http::Response::new(frames_body(b"download")))
            }
        })
        .boxed_clone();
        let serving = tokio::spawn(serve_exchange(
            app,
            response_writer,
            request_reader,
            server.qpack().clone(),
            handshake("bob.dhttp.net"),
        ));
        let message = http::Request::builder()
            .method("POST")
            .uri("https://bob~:70000/upload")
            .body(frames_body(b"upload"))
            .unwrap();
        let response = send_request(message, writer, reader, client.qpack().clone())
            .await
            .unwrap();
        observed.await.unwrap();
        let collected = response.into_body().collect().await.unwrap();
        assert_eq!(
            collected
                .trailers()
                .unwrap()
                .get_all("x-tag")
                .iter()
                .count(),
            2
        );
        assert_eq!(collected.to_bytes(), "download");
        serving.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn inbound_authority_must_match_handshake_before_service() {
    bounded(async {
        let missing_local = Arc::new(qtls::HandshakeSummary {
            local: None,
            remote: None,
            alpn: Some(Bytes::from_static(h3x::ALPN)),
        });
        for (uri, handshake) in [
            ("https://alice.dhttp.net/", handshake("bob.dhttp.net")),
            ("https://user@bob.dhttp.net/", handshake("bob.dhttp.net")),
            ("/", handshake("bob.dhttp.net")),
            ("https://bob.dhttp.net/", missing_local),
        ] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (response_writer, request_reader) = server.accept_bi().await.unwrap();
            let app = tower::service_fn(|_: http::Request<Body>| async {
                Ok::<_, BoxError>(http::Response::new(
                    Empty::<Bytes>::new().map_err(Into::into).boxed_unsync(),
                ))
            })
            .boxed_clone();
            let serving = tokio::spawn(serve_exchange(
                app,
                response_writer,
                request_reader,
                server.qpack().clone(),
                handshake,
            ));
            let request = http::Request::builder()
                .uri(uri)
                .body(Full::new(Bytes::from(vec![42; BODY_WINDOW_BYTES * 8])))
                .unwrap();
            let response = send_request(request, writer, reader, client.qpack().clone())
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::MISDIRECTED_REQUEST);
            serving.await.unwrap().unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn response_headers_arrive_before_upload_eof() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let (release, released) = tokio::sync::oneshot::channel();
        let upload = StreamBody::new(async_stream::stream! {
            released.await.unwrap();
            yield Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"after response headers")));
        });
        let qpack = server.qpack().clone();
        let server_task = tokio::spawn(async move {
            let mut request = request_reader.read_request(qpack.clone()).await.unwrap();
            let response = http::Response::new(Full::new(Bytes::from_static(b"early")));
            let reading = async {
                let mut bytes = Vec::new();
                request.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"after response headers");
            };
            let (result, ()) = tokio::join!(
                send_response(response, http::Method::POST, response_writer, qpack),
                reading
            );
            result.unwrap();
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(upload)
            .unwrap();
        let response = send_request(request, writer, reader, client.qpack().clone())
            .await
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "early"
        );
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn dropping_outbound_request_future_stops_upload() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (_response_writer, request_reader) = server.accept_bi().await.unwrap();
        let (started, observed_start) = tokio::sync::oneshot::channel();
        let (dropped, observed_drop) = tokio::sync::oneshot::channel();
        let guard = scopeguard::guard(dropped, |sender| {
            let _ = sender.send(());
        });
        let body = StreamBody::new(async_stream::stream! {
            let _guard = guard;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
            yield Ok::<_, BoxError>(Frame::data(Bytes::new()));
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(body)
            .unwrap();
        let sending = tokio::spawn(send_request(
            request,
            writer,
            reader,
            client.qpack().clone(),
        ));
        let incoming = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        observed_start.await.unwrap();
        sending.abort();
        let _ = sending.await;
        observed_drop.await.unwrap();
        drop(incoming);
    })
    .await;
}

#[tokio::test]
async fn dropping_outbound_response_body_stops_upload() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let (started, observed_start) = tokio::sync::oneshot::channel();
        let (dropped, observed_drop) = tokio::sync::oneshot::channel();
        let guard = scopeguard::guard(dropped, |sender| {
            let _ = sender.send(());
        });
        let body = StreamBody::new(async_stream::stream! {
            let _guard = guard;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
            yield Ok::<_, BoxError>(Frame::data(Bytes::new()));
        });
        let (release, released) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let incoming = request_reader
                .read_request(server.qpack().clone())
                .await
                .unwrap();
            send_response(
                http::Response::new(Full::new(Bytes::from_static(b"early"))),
                http::Method::POST,
                response_writer,
                server.qpack().clone(),
            )
            .await
            .unwrap();
            released.await.unwrap();
            drop(incoming);
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(body)
            .unwrap();
        let response = send_request(request, writer, reader, client.qpack().clone())
            .await
            .unwrap();
        observed_start.await.unwrap();
        drop(response);
        observed_drop.await.unwrap();
        release.send(()).unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn dropped_request_body_does_not_cancel_early_service_response() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let app = tower::service_fn(|request: http::Request<Body>| async move {
            drop(request);
            Ok::<_, BoxError>(http::Response::new(
                Full::new(Bytes::from_static(b"rejected early"))
                    .map_err(Into::into)
                    .boxed_unsync(),
            ))
        })
        .boxed_clone();
        let serving = tokio::spawn(serve_exchange(
            app,
            response_writer,
            request_reader,
            server.qpack().clone(),
            handshake("bob.dhttp.net"),
        ));
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(Full::new(Bytes::from(vec![42; BODY_WINDOW_BYTES * 8])))
            .unwrap();
        let response = send_request(request, writer, reader, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "rejected early"
        );
        serving.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn outbound_request_preserves_target_error_categories() {
    let endpoint = Endpoint::load("alice").await.unwrap();

    let error = endpoint
        .get("ftp://bob~/x".parse().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidRequest { message } if message == "unsupported URI scheme"
    ));

    let error = endpoint
        .get("https://bad_name/x".parse().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidName { name } if name == "bad_name"
    ));
}

#[tokio::test]
async fn suppressed_response_body_drops_unpolled_producer_and_preserves_headers() {
    bounded(async {
        for (method, status) in [
            (http::Method::HEAD, http::StatusCode::OK),
            (http::Method::GET, http::StatusCode::NO_CONTENT),
            (http::Method::GET, http::StatusCode::NOT_MODIFIED),
        ] {
            let (client, server) = support::connection_pair();
            let (_writer, reader) = client.open_bi().await.unwrap();
            let (writer, _reader) = server.accept_bi().await.unwrap();
            let (dropped, observed) = tokio::sync::oneshot::channel();
            let response = http::Response::builder()
                .status(status)
                .header("x-result", "preserved")
                .body(pending_body(dropped))
                .unwrap();
            send_response(response, method.clone(), writer, server.qpack().clone())
                .await
                .unwrap();
            observed.await.unwrap();
            let mut response = reader
                .read_response(method, client.qpack().clone())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["x-result"], "preserved");
            assert_eq!(response.read_to_end(&mut Vec::new()).await.unwrap(), 0);
        }
    })
    .await;
}

#[tokio::test]
async fn body_failure_is_an_error_instead_of_clean_eof() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (_writer, reader) = client.open_bi().await.unwrap();
        let (writer, _reader) = server.accept_bi().await.unwrap();
        let (fail, fail_after_partial) = tokio::sync::oneshot::channel::<()>();
        let body = StreamBody::new(async_stream::stream! {
            yield Ok::<Frame<Bytes>, BoxError>(Frame::data(Bytes::from_static(b"partial")));
            fail_after_partial.await.unwrap();
            yield Err::<Frame<Bytes>, BoxError>(Box::new(std::io::Error::other("producer failed")));
        });
        let writing = send_response(
            http::Response::new(body),
            http::Method::GET,
            writer,
            server.qpack().clone(),
        );
        let reading = async {
            let mut response = reader
                .read_response(http::Method::GET, client.qpack().clone())
                .await
                .unwrap();
            let mut partial = [0; 7];
            response.read_exact(&mut partial).await.unwrap();
            assert_eq!(&partial, b"partial");
            fail.send(()).unwrap();
            let error = response.read_to_end(&mut Vec::new()).await.unwrap_err();
            assert_eq!(
                h3x::Error::from(error).code,
                h3x::ErrorCode::RequestCancelled
            );
        };
        let (result, ()) = tokio::join!(writing, reading);
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn upload_failure_ends_request_while_response_is_pending() {
    bounded(async {
        let (client, _server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let body = StreamBody::new(futures::stream::iter([Err::<Frame<Bytes>, BoxError>(
            Box::new(std::io::Error::other("upload failed")),
        )]));
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob.dhttp.net/upload")
            .body(body)
            .unwrap();
        assert!(
            send_request(request, writer, reader, client.qpack().clone())
                .await
                .is_err()
        );
    })
    .await;
}

#[derive(Clone)]
struct ReadinessFailure;
impl Service<http::Request<Body>> for ReadinessFailure {
    type Response = http::Response<Body>;
    type Error = BoxError;
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), BoxError>> {
        std::task::Poll::Ready(Err(Box::new(std::io::Error::other("readiness failed"))))
    }
    fn call(&mut self, _: http::Request<Body>) -> Self::Future {
        panic!("call must not run after readiness failure")
    }
}

#[tokio::test]
async fn service_call_and_readiness_failures_return_errors() {
    bounded(async {
        for app in [
            ReadinessFailure.boxed_clone(),
            tower::service_fn(|_: http::Request<Body>| async {
                Err::<http::Response<Body>, BoxError>(Box::new(std::io::Error::other(
                    "service failed",
                )))
            })
            .boxed_clone(),
        ] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (response_writer, request_reader) = server.accept_bi().await.unwrap();
            let mut body = h3x::ArcWndBuf::new(32);
            body.shutdown().await.unwrap();
            let request = http::Request::builder()
                .uri("https://bob.dhttp.net/")
                .body(body)
                .unwrap()
                .into();
            writer
                .write_request(request, client.qpack().clone())
                .await
                .unwrap();
            let serving = serve_exchange(
                app,
                response_writer,
                request_reader,
                server.qpack().clone(),
                handshake("bob.dhttp.net"),
            );
            let reading = reader.read_response(http::Method::GET, client.qpack().clone());
            let (result, response) = tokio::join!(serving, reading);
            assert!(result.is_err());
            assert_eq!(
                response.err().unwrap().code,
                h3x::ErrorCode::RequestCancelled
            );
        }
    })
    .await;
}

#[tokio::test]
async fn malformed_request_fails_peer_promptly() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (mut writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        writer.write_all(&[0, 1, 42]).await.unwrap(); // DATA before HEADERS is invalid.
        writer.shutdown().await.unwrap();
        let serving = serve_exchange(
            ReadinessFailure.boxed_clone(),
            response_writer,
            request_reader,
            server.qpack().clone(),
            handshake("bob.dhttp.net"),
        );
        let reading = reader.read_response(http::Method::GET, client.qpack().clone());
        let (result, response) = tokio::join!(serving, reading);
        assert!(result.is_err());
        let error = response.err().unwrap();
        assert!(matches!(
            error.code,
            h3x::ErrorCode::RequestCancelled | h3x::ErrorCode::FrameUnexpected
        ));
    })
    .await;
}
