use dhttp_api::{endpoint::Endpoint, stream};

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
