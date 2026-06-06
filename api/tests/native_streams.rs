use dhttp_api::{
    endpoint::{Endpoint, incoming::IncomingStream},
    stream,
};

#[tokio::test]
async fn endpoint_connect_exposes_connection_future() {
    let endpoint = Endpoint::create(None).await.unwrap();

    let future = endpoint.connect("example.com");
    drop(future);
}

#[test]
fn stream_types_are_public_to_rust_wrapper_layer() {
    fn assert_send<T: Send>() {}

    assert_send::<stream::ReadStream>();
    assert_send::<stream::WriteStream>();
}

#[test]
fn incoming_stream_type_is_public_to_rust_wrapper_layer() {
    fn assert_send<T: Send>() {}

    assert_send::<IncomingStream>();
}

#[tokio::test]
async fn endpoint_listen_streams_exposes_low_level_handler() {
    let endpoint = Endpoint::create(None).await.unwrap();

    let handle = endpoint.listen_streams(|incoming| {
        Box::pin(async move {
            let _stream_id = incoming.stream_id();
            let (_read_stream, _write_stream) = incoming.into_parts();
            Ok(())
        })
    });

    handle.abort();
    handle.closed().await.unwrap();
}

#[test]
fn unresolved_request_type_is_public_to_rust_wrapper_layer() {
    fn assert_send<T: Send>() {}

    assert_send::<dhttp_api::endpoint::unresolved::UnresolvedRequest>();
}

#[allow(dead_code)]
async fn endpoint_raw_request_api_is_exposed(
    endpoint: &dhttp_api::endpoint::Endpoint,
    connection: &dhttp_api::endpoint::connection::Connection,
    request: dhttp_api::endpoint::unresolved::UnresolvedRequest,
) {
    let _connection = endpoint.connect("example.com").await.unwrap();
    let _request = connection.open_request().await.unwrap();

    let _stream_id = request.stream_id();
    let _local = request.local_authority();
    let _remote = request.remote_authority();
    let (_reader, _writer) = request.into_parts();
}

#[tokio::test]
async fn endpoint_listen_raw_exposes_unresolved_request_handler() {
    let endpoint = dhttp_api::endpoint::Endpoint::create(None).await.unwrap();

    let handle = endpoint.listen_raw(|request| {
        Box::pin(async move {
            let _stream_id = request.stream_id();
            let (_reader, _writer) = request.into_parts();
            Ok(())
        })
    });

    handle.abort();
    handle.closed().await.unwrap();
}
