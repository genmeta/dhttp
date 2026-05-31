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
