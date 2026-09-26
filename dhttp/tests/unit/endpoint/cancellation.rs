#[tokio::test]
async fn dropping_unpolled_response_cancels_both_directions_and_releases_upload() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (response_writer, request_reader) = server.accept_bi().await.unwrap();
        let qpack = server.qpack().clone();
        let (ready, started) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut request = request_reader.read_request(qpack.clone()).await.unwrap();
            let native = h3x::ArcWndBuf::new(32);
            let mut producer = native.clone();
            let response = http::Response::new(native).into();
            let writing = response_writer.write_response(response, http::Method::POST, qpack);
            let reading = async {
                let _ = ready.send(());
                assert!(request.read_to_end(&mut Vec::new()).await.is_err());
                // Native stop/error is observed at I/O. An idle remote producer
                // is not a notification future, so let its next write progress.
                let _ = producer.write_all(b"late").await;
            };
            let (result, ()) = tokio::join!(writing, reading);
            assert!(result.is_err());
        });
        let (dropped, observed) = tokio::sync::oneshot::channel();
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(pending_body(dropped))
            .unwrap();
        let response = send_request(
            request,
            writer,
            reader,
            client.qpack().clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        started.await.unwrap();
        drop(response);
        observed.await.unwrap();
        server_task.await.unwrap();
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
async fn service_call_and_readiness_failures_explicitly_reset_response_stream() {
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
                handshake(),
            );
            let reading = reader.read_response(http::Method::GET, client.qpack().clone());
            let (result, response) = tokio::join!(serving, reading);
            assert!(result.is_err());
            // Duplex Drop would only yield EOF. The protocol code proves that
            // an explicit native reset reached the peer.
            assert_eq!(
                response.err().unwrap().code,
                h3x::ErrorCode::RequestCancelled
            );
        }
    })
    .await;
}

#[tokio::test]
async fn unpolled_exchange_and_response_futures_explicitly_reset_native_writer() {
    bounded(async {
        for response_only in [false, true] {
            let (client, server) = support::connection_pair();
            let (_writer, reader) = client.open_bi().await.unwrap();
            let (writer, request_reader) = server.accept_bi().await.unwrap();
            if response_only {
                drop(send_response(
                    http::Response::new(Empty::<Bytes>::new()),
                    http::Method::GET,
                    writer,
                    server.qpack().clone(),
                ));
                drop(request_reader);
            } else {
                drop(serve_exchange(
                    ReadinessFailure.boxed_clone(),
                    writer,
                    request_reader,
                    server.qpack().clone(),
                    handshake(),
                ));
            }
            let error = reader
                .read_response(http::Method::GET, client.qpack().clone())
                .await
                .err()
                .unwrap();
            assert_eq!(error.code, h3x::ErrorCode::RequestCancelled);
        }
    })
    .await;
}

#[tokio::test]
async fn malformed_request_fails_peer_without_waiting_for_response_timeout() {
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
            handshake(),
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

#[tokio::test]
async fn response_producer_failure_resets_native_writer_before_it_is_dropped() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (_writer, reader) = client.open_bi().await.unwrap();
        let (writer, _reader) = server.accept_bi().await.unwrap();
        let body = StreamBody::new(futures::stream::iter([Err::<Frame<Bytes>, BoxError>(
            Box::new(std::io::Error::other("first frame failed")),
        )]));
        let writing = send_response(
            http::Response::new(body),
            http::Method::GET,
            writer,
            server.qpack().clone(),
        );
        let reading = async {
            match reader
                .read_response(http::Method::GET, client.qpack().clone())
                .await
            {
                Ok(mut response) => h3x::Error::from_stream_io(
                    response.read_to_end(&mut Vec::new()).await.err().unwrap(),
                ),
                Err(error) => error,
            }
        };
        let (result, error) = tokio::join!(writing, reading);
        assert!(result.is_err());
        assert_eq!(error.code, h3x::ErrorCode::RequestCancelled);
    })
    .await;
}

#[tokio::test]
async fn cancelling_response_headers_stops_native_input_after_upload_fin_or_no_error() {
    bounded(async {
        for early_stop in [false, true] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (_response_writer, request_reader) = server.accept_bi().await.unwrap();
            let body = Full::new(if early_stop {
                Bytes::from(vec![42; BODY_WINDOW_BYTES * 8])
            } else {
                Bytes::new()
            });
            let request = http::Request::builder()
                .method("POST")
                .uri("https://bob.dhttp.net/upload")
                .body(body)
                .unwrap();
            let qpack = client.qpack().clone();
            let exchange = tokio::spawn(send_request(
                request,
                writer,
                reader,
                qpack,
                CancellationToken::new(),
            ));
            let mut request = request_reader
                .read_request(server.qpack().clone())
                .await
                .unwrap();
            if early_stop {
                request.stop(h3x::ErrorCode::NoError.as_u64());
            } else {
                request.read_to_end(&mut Vec::new()).await.unwrap();
            }
            tokio::task::yield_now().await;
            exchange.abort();
            let _ = exchange.await;
            // Check the native STOP action directly: merely dropping a duplex
            // reader would close its memory pipe but would not record a code.
            while !client
                .transport()
                .stops()
                .contains(&h3x::ErrorCode::RequestCancelled.as_u64())
            {
                tokio::task::yield_now().await;
            }
        }
    })
    .await;
}
