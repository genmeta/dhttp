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
            handshake(),
        ));
        let message = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(frames_body(b"upload"))
            .unwrap();
        let response = send_request(
            message,
            writer,
            reader,
            client.qpack().clone(),
            CancellationToken::new(),
        )
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
        let response = send_request(
            request,
            writer,
            reader,
            client.qpack().clone(),
            CancellationToken::new(),
        )
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
            handshake(),
        ));
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bob~/upload")
            .body(Full::new(Bytes::from(vec![42; BODY_WINDOW_BYTES * 8])))
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
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "rejected early"
        );
        serving.await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn outbound_uri_expands_identity_shorthand_before_routing() {
    let endpoint = Endpoint::load("alice").await.unwrap();
    let other = canonical_uri(&endpoint, &"https://bob~/upload?q=1".parse().unwrap()).unwrap();
    assert_eq!(other.to_string(), "https://bob.dhttp.net/upload?q=1");
    assert_eq!(remote_name(&other).unwrap().as_ref(), "bob.dhttp.net");
    let local = canonical_uri(&endpoint, &"https://~/self".parse().unwrap()).unwrap();
    assert_eq!(local.to_string(), "https://alice.dhttp.net/self");
}
