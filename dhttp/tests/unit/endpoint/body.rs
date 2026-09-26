#[tokio::test]
async fn unpolled_receiving_body_drop_stops_native_input() {
    let inbound = h3x::ArcWndBuf::new(32);
    let mut producer = inbound.clone();
    let body = receiving_body(inbound, h3x::Trailers::new(), h3x::ErrorCode::NoError);
    drop(body);
    assert!(producer.write_all(b"late").await.is_err());
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
        let body = StreamBody::new(futures::stream::iter([
            Ok(Frame::data(Bytes::from_static(b"partial"))),
            Err::<Frame<Bytes>, BoxError>(Box::new(std::io::Error::other("producer failed"))),
        ]));
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
                Ok(mut response) => assert!(response.read_to_end(&mut Vec::new()).await.is_err()),
                Err(_) => {}
            }
        };
        let (result, ()) = tokio::join!(writing, reading);
        assert!(result.is_err());
    })
    .await;
}
