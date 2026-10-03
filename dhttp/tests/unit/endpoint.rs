//! Transport-independent tests: all HTTP/3 traffic stays inside Tokio duplex streams.
use super::request::{send_empty_request, send_request as send_upload};
use super::*;
use h3x::{ReadResponse, WriteRequest};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use std::{sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

fn window(initial: Bytes) -> WndBuf {
    WndBuf::with_initial(super::request::REQUEST_WINDOW_BYTES, initial)
}

#[tokio::test]
async fn anonymous_endpoint_requests_require_an_explicit_remote_name() {
    let endpoint = Endpoint::new(None);
    assert_eq!(endpoint.name(), None);
    assert!(endpoint.quic.is_none());
    let standard = Request::new(
        http::Request::builder()
            .uri("https://~/profile")
            .body(Empty::<Bytes>::new())
            .unwrap(),
    );
    assert!(
        matches!(standard.await, Err(Error::InvalidRequest { message })
        if message == "cannot expand bare dhttp shorthand without a base name")
    );
    let error = endpoint
        .get("https://~/profile".parse().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidRequest { message }
            if message == "cannot expand bare dhttp shorthand without a base name"
    ));
}

#[tokio::test]
async fn builder_works_without_network_and_preserves_headers_when_replacing_body() {
    let endpoint = test_support::named("ALICE");
    assert_eq!(endpoint.name(), Some("alice.dhttp.net"));
    let uri = "https://bob~/upload".parse().unwrap();
    let request = endpoint
        .get(uri)
        .header(http::header::ACCEPT, http::HeaderValue::from_static("one"))
        .append_header(http::header::ACCEPT, http::HeaderValue::from_static("two"))
        .trailer(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("replaced"),
        )
        .trailer(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("one"),
        )
        .append_trailer(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("two"),
        )
        .body(window(Bytes::from_static(b"initial")))
        .body(window(Bytes::from_static(b"replacement")));
    let mut body = request.message.body().clone();
    let mut bytes = [0; 11];
    body.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"replacement");
    let request = request.body(Empty::<Bytes>::new());
    let (parts, body) = request.message.into_parts();
    assert!(http_body::Body::is_end_stream(&body));
    assert_eq!(
        parts.headers.get_all(http::header::ACCEPT).iter().count(),
        2
    );
    assert_eq!(parts.method, http::Method::GET);
    let trailers = parts.extensions.get::<h3x::Trailers>().unwrap().headers();
    assert_eq!(
        trailers.get_all("x-tag").iter().collect::<Vec<_>>(),
        ["one", "two"]
    );
}

#[tokio::test]
async fn request_writer_sends_preset_and_updated_trailers_on_shutdown() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let qpack = server.qpack().clone();
        let serving = tokio::spawn(async move {
            let request = request_reader.read_request(qpack.clone()).await.unwrap();
            let collected = request.into_body().collect().await.unwrap();
            let trailers = collected.trailers().unwrap();
            assert_eq!(
                trailers.get_all("x-tag").iter().collect::<Vec<_>>(),
                ["initial", "before-send", "after-send"]
            );
            assert_eq!(
                trailers.get_all("x-checksum").iter().collect::<Vec<_>>(),
                ["computed"]
            );
            assert!(trailers.get("x-checksum").unwrap().is_sensitive());
            assert_eq!(collected.to_bytes(), "initial-chunk-one-chunk-two");
            send_response(
                http::Response::new(Empty::<Bytes>::new()),
                http::Method::POST,
                response_writer,
                qpack,
            )
            .await
            .unwrap();
        });
        let tag = http::HeaderName::from_static("x-tag");
        let checksum = http::HeaderName::from_static("x-checksum");
        let message = test_support::named("alice")
            .post("https://example.com/".parse().unwrap())
            .trailer(tag.clone(), http::HeaderValue::from_static("initial"))
            .append_trailer(tag.clone(), http::HeaderValue::from_static("before-send"))
            .trailer(
                checksum.clone(),
                http::HeaderValue::from_static("placeholder"),
            )
            .append_trailer(
                checksum.clone(),
                http::HeaderValue::from_static("also-replaced"),
            )
            .write(b"discarded")
            .body(window(Bytes::from_static(b"initial-")))
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        upload.write_all(b"chunk-one-").await.unwrap();
        upload
            .append_trailer(tag.clone(), http::HeaderValue::from_static("after-send"))
            .unwrap();
        // Registering trailers must not prevent further DATA writes.
        upload.write_all(b"chunk-two").await.unwrap();
        let mut computed = http::HeaderValue::from_static("computed");
        computed.set_sensitive(true);
        upload.trailer(checksum.clone(), computed).unwrap();
        upload.shutdown().await.unwrap();
        upload.shutdown().await.unwrap();
        assert_eq!(
            upload
                .trailer(checksum, http::HeaderValue::from_static("late"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            upload
                .append_trailer(tag, http::HeaderValue::from_static("late"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            upload.write_all(b"late").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(response.await.unwrap().status(), 200);
        serving.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn empty_requests_send_preset_trailers_automatically() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let qpack = server.qpack().clone();
        let serving = tokio::spawn(async move {
            let request = request_reader.read_request(qpack.clone()).await.unwrap();
            let collected = request.into_body().collect().await.unwrap();
            assert_eq!(collected.trailers().unwrap()["x-tag"], "empty");
            assert!(collected.to_bytes().is_empty());
            send_response(
                http::Response::new(Empty::<Bytes>::new()),
                http::Method::GET,
                response_writer,
                qpack,
            )
            .await
            .unwrap();
        });
        let message = Request::new(
            http::Request::builder()
                .uri("https://example.com/")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .trailer(
            http::HeaderName::from_static("x-tag"),
            http::HeaderValue::from_static("empty"),
        )
        .message;
        let response = send_empty_request(message, writer, reader, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serving.await.unwrap();
    })
    .await;
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
        let serving = tokio::spawn(handle_request(
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
        let (_upload, response) = send_request(message, writer, reader, client.qpack().clone())
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
            ("https://bob/", handshake("bob.dhttp.net")),
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
            let serving = tokio::spawn(handle_request(
                app,
                response_writer,
                request_reader,
                server.qpack().clone(),
                handshake,
            ));
            let request = http::Request::builder()
                .uri(uri)
                .body(Full::new(Bytes::from(vec![42; 512 * 1024])))
                .unwrap();
            let (_upload, response) = send_request(request, writer, reader, client.qpack().clone())
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
        let qpack = server.qpack().clone();
        let server_task = tokio::spawn(async move {
            let request = request_reader.read_request(qpack.clone()).await.unwrap();
            send_response(
                http::Response::new(Full::new(Bytes::from_static(b"early"))),
                http::Method::POST,
                response_writer,
                qpack,
            )
            .await
            .unwrap();
            request.into_body().collect().await.unwrap().to_bytes()
        });
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        let response = response.await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "early"
        );
        upload.write_all(b"after response headers").await.unwrap();
        upload.shutdown().await.unwrap();
        assert_eq!(server_task.await.unwrap(), "after response headers");
    })
    .await;
}

#[tokio::test]
async fn dropping_request_writer_resets_unfinished_upload() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (_response_writer, request_reader) = server.accept_bi().await.unwrap();
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .message;
        let (upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        let incoming = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        drop(upload);
        let error = incoming.into_body().collect().await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<h3x::Error>().unwrap().code,
            h3x::ErrorCode::RequestCancelled
        );
        drop(response);
    })
    .await;
}

#[tokio::test]
async fn response_drop_keeps_upload_alive_until_the_writer_is_cancelled() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let (seen, observed) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut incoming = request_reader
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
            let frame = incoming.body_mut().frame().await.unwrap().unwrap();
            assert_eq!(frame.into_data().unwrap(), "after response drop");
            seen.send(()).unwrap();
            incoming.into_body().collect().await.unwrap_err()
        });
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        drop(response.await.unwrap());
        upload.write_all(b"after response drop").await.unwrap();
        observed.await.unwrap();
        upload.cancel(h3x::ErrorCode::RequestRejected.as_u64());
        let error = server_task.await.unwrap();
        assert_eq!(
            error.downcast_ref::<h3x::Error>().unwrap().code,
            h3x::ErrorCode::RequestRejected
        );
    })
    .await;
}

#[tokio::test]
async fn cancelling_before_the_upload_task_is_polled_preserves_the_code() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (_response_writer, request_reader) = server.accept_bi().await.unwrap();
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .body(window(Bytes::from_static(b"initial")))
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        upload.cancel(h3x::ErrorCode::RequestRejected.as_u64());
        drop(upload);
        let error = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap_err();
        assert_eq!(error.code, h3x::ErrorCode::RequestRejected);
        drop(response);
    })
    .await;
}

#[tokio::test]
async fn response_failure_closes_the_writers_window() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (mut response_writer, request_reader) = server.accept_bi().await.unwrap();
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        let incoming = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        response_writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
        assert!(response.await.is_err());
        assert!(upload.write_all(b"after failure").await.is_err());
        assert!(upload.shutdown().await.is_err());
        drop(incoming);
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
        let serving = tokio::spawn(handle_request(
            app,
            response_writer,
            request_reader,
            server.qpack().clone(),
            handshake("bob.dhttp.net"),
        ));
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(Full::new(Bytes::from(vec![42; 512 * 1024])))
            .unwrap();
        let (_upload, response) = send_request(request, writer, reader, client.qpack().clone())
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
    let endpoint = test_support::named("alice");

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
            let response = reader
                .read_response(method, client.qpack().clone())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["x-result"], "preserved");
            assert!(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
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
            let partial = response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            assert_eq!(partial, "partial");
            fail.send(()).unwrap();
            let error = response.into_body().collect().await.unwrap_err();
            assert_eq!(
                error.downcast_ref::<h3x::Error>().unwrap().code,
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
            let body = Body::default();
            let request = http::Request::builder()
                .uri("https://bob.dhttp.net/")
                .body(body)
                .unwrap();
            writer
                .write_request(request, client.qpack().clone())
                .await
                .unwrap();
            let serving = handle_request(
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
        let serving = handle_request(
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

async fn send_response<B, W>(
    response: http::Response<B>,
    method: http::Method,
    writer: W,
    qpack: h3x::ArcQpack,
) -> Result<()>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    W: WriteResponse,
{
    writer
        .write_response(
            response.map(|body| body.map_err(Into::into).boxed_unsync()),
            method,
            qpack,
        )
        .await
        .map_err(Error::from)
}

#[test]
fn request_entry_points_have_the_expected_output_types() {
    fn response_only(_: impl std::future::IntoFuture<Output = Result<http::Response<Body>>>) {}
    fn with_writer(
        _: impl std::future::IntoFuture<Output = Result<(RequestWriter, crate::RequestFuture)>>,
    ) {
    }
    let endpoint = Endpoint::new(None);
    let uri: http::Uri = "https://example.com/".parse().unwrap();
    response_only(endpoint.get(uri.clone()));
    response_only(endpoint.head(uri.clone()));
    response_only(endpoint.delete(uri.clone()));
    response_only(endpoint.options(uri.clone()));
    response_only(endpoint.post(uri.clone()).body(Empty::<Bytes>::new()));
    with_writer(endpoint.post(uri.clone()));
    with_writer(endpoint.put(uri.clone()));
    with_writer(endpoint.patch(uri.clone()));
    with_writer(endpoint.request(http::Method::GET, uri.clone()));
    with_writer(endpoint.post(uri.clone()).write(b"initial"));
    with_writer(
        endpoint
            .post(uri)
            .body(window(Bytes::from_static(b"initial"))),
    );
}

#[tokio::test]
async fn empty_requests_send_eof_before_waiting_for_response() {
    bounded(async {
        let endpoint = Endpoint::new(None);
        let uri: http::Uri = "https://example.com/".parse().unwrap();
        for request in [
            endpoint.get(uri.clone()),
            endpoint.head(uri.clone()),
            endpoint.delete(uri.clone()),
            endpoint.options(uri.clone()),
            endpoint.post(uri.clone()).body(Empty::<Bytes>::new()),
        ] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (response_writer, request_reader) = server.accept_bi().await.unwrap();
            let method = request.message.method().clone();
            let serving = tokio::spawn(async move {
                let incoming = request_reader
                    .read_request(server.qpack().clone())
                    .await
                    .unwrap();
                assert_eq!(incoming.method(), method);
                assert!(
                    incoming
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .is_empty()
                );
                send_response(
                    http::Response::builder()
                        .status(204)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                    method,
                    response_writer,
                    server.qpack().clone(),
                )
                .await
                .unwrap();
            });
            let response =
                send_empty_request(request.message, writer, reader, client.qpack().clone())
                    .await
                    .unwrap();
            assert_eq!(response.status(), 204);
            serving.await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn empty_requests_accept_no_error_stop_but_propagate_upload_failures() {
    struct StoppedUpload(h3x::ErrorCode);
    impl WriteRequest<Empty<Bytes>> for StoppedUpload {
        async fn write_request(
            self,
            _: http::Request<Empty<Bytes>>,
            _: h3x::ArcQpack,
        ) -> h3x::Result<()> {
            Err(self.0.stream("peer stopped uploading"))
        }
    }
    struct Response;
    impl ReadResponse for Response {
        async fn read_response(
            self,
            _: http::Method,
            _: h3x::ArcQpack,
        ) -> h3x::Result<http::Response<Body>> {
            Ok(http::Response::new(Body::default()))
        }
    }
    let (client, _server) = support::connection_pair();
    for code in [h3x::ErrorCode::NoError, h3x::ErrorCode::RequestRejected] {
        let request = http::Request::builder()
            .uri("https://example.com/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let result = send_empty_request(
            request,
            StoppedUpload(code),
            Response,
            client.qpack().clone(),
        )
        .await;
        if code == h3x::ErrorCode::NoError {
            assert_eq!(result.unwrap().status(), http::StatusCode::OK);
        } else {
            assert!(matches!(result, Err(Error::Http3 { source }) if source.code == code));
        }
    }
}

#[tokio::test]
async fn window_requests_can_shutdown_before_the_server_returns_headers() {
    bounded(async {
        for mode in ["post", "write", "body", "from_request"] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (response_writer, request_reader) = server.accept_bi().await.unwrap();
            let qpack = server.qpack().clone();
            let serving = tokio::spawn(async move {
                let request = request_reader.read_request(qpack.clone()).await.unwrap();
                // The server requires EOF before it can send response headers.
                let body = request.into_body().collect().await.unwrap().to_bytes();
                send_response(
                    http::Response::builder()
                        .status(201)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                    http::Method::POST,
                    response_writer,
                    qpack,
                )
                .await
                .unwrap();
                body
            });
            let endpoint = Endpoint::new(None);
            let request = endpoint.post("https://example.com/".parse().unwrap());
            let initial = Bytes::from(vec![0x5a; 96 * 1024]);
            let request = match mode {
                "post" => request,
                "write" => request.write(&initial),
                "body" => request.body(window(initial.clone())),
                "from_request" => Request::new(
                    http::Request::builder()
                        .method("POST")
                        .uri("https://example.com/")
                        .body(window(initial.clone()))
                        .unwrap(),
                ),
                _ => unreachable!(),
            };
            let message = request.message;
            let (mut upload, response) =
                send_upload(message, writer, reader, client.qpack().clone());
            upload.write_all(&vec![42; 128 * 1024]).await.unwrap();
            upload.shutdown().await.unwrap();
            upload.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
            let response = response.await.unwrap();
            assert_eq!(response.status(), 201);
            let mut expected = if mode == "post" {
                vec![]
            } else {
                initial.to_vec()
            };
            expected.extend_from_slice(&vec![42; 128 * 1024]);
            assert_eq!(serving.await.unwrap(), expected);
            assert_eq!(
                upload.write_all(b"after EOF").await.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
        }
    })
    .await;
}

#[tokio::test]
async fn cancelling_shutdown_does_not_detach_the_owned_upload() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let message = Endpoint::new(None)
            .post("https://example.com/".parse().unwrap())
            .body(window(Bytes::from(vec![42; 2 * 1024 * 1024])))
            .message;
        let (mut upload, response) = send_upload(message, writer, reader, client.qpack().clone());
        let incoming = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        send_response(
            http::Response::new(Empty::<Bytes>::new()),
            http::Method::POST,
            response_writer,
            server.qpack().clone(),
        )
        .await
        .unwrap();
        let response = response.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), upload.shutdown())
                .await
                .is_err()
        );
        for append in [false, true] {
            let name = http::HeaderName::from_static("x-late");
            let value = http::HeaderValue::from_static("rejected");
            let result = if append {
                upload.append_trailer(name, value)
            } else {
                upload.trailer(name, value)
            };
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        }
        drop(upload);
        let error = incoming.into_body().collect().await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<h3x::Error>().unwrap().code,
            h3x::ErrorCode::RequestCancelled
        );
        drop(response);
    })
    .await;
}

// Standard Body fixtures exercise the h3x service boundary; fluent requests use send_upload.
type BodyUpload = scopeguard::ScopeGuard<
    tokio::task::JoinHandle<h3x::Result<()>>,
    fn(tokio::task::JoinHandle<h3x::Result<()>>),
>;

async fn send_request<B, W, R>(
    message: http::Request<B>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
) -> Result<(BodyUpload, http::Response<Body>)>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    W: WriteRequest + 'static,
    R: ReadResponse + 'static,
{
    let method = message.method().clone();
    let message = message.map(|body| body.map_err(Into::into).boxed_unsync());
    let upload: BodyUpload = scopeguard::guard(
        tokio::spawn(writer.write_request(message, qpack.clone())),
        |upload| upload.abort(),
    );
    let response = reader.read_response(method, qpack).await?;
    Ok((upload, response))
}
