#![cfg(feature = "pyo3")]

use pyo3::prelude::*;

#[tokio::test]
async fn pyo3_minimal_endpoint_api_is_constructible() {
    let home = dhttp_api::pyo3::Home::new("/tmp/dhttp-api-pyo3".to_string());
    assert_eq!(home.path(), "/tmp/dhttp-api-pyo3");

    let mut options = dhttp_api::pyo3::EndpointOptions::new();
    options.add_bind_pattern("*".to_string()).unwrap();
    assert_eq!(options.bind_patterns(), vec!["iface://*".to_string()]);

    let endpoint = dhttp_api::pyo3::Endpoint::create(None).await.unwrap();
    assert!(endpoint.identity().is_none());

    let request = endpoint.request();
    request.set_method("POST".to_string()).unwrap();
    request
        .set_uri("https://example.com/api".to_string())
        .unwrap();
    request
        .header("content-type".to_string(), "text/plain".to_string())
        .unwrap();
    request.body(b"hello".to_vec()).unwrap();
    request
        .trailer("x-trailer".to_string(), "done".to_string())
        .unwrap();

    let _get = endpoint.get("https://example.com/".to_string()).unwrap();
    let _post = endpoint.post("https://example.com/".to_string()).unwrap();
}

#[allow(dead_code)]
async fn pyo3_client_response_api_is_exposed(
    request: dhttp_api::pyo3::ClientRequest,
    response: &dhttp_api::pyo3::ClientResponse,
) {
    request.write(b"chunk".to_vec()).await.unwrap();
    request.flush().await.unwrap();
    request.close().await.unwrap();
    request.cancel(0).await.unwrap();

    let _response = request.response().await.unwrap();
    let _response = request.into_response().await.unwrap();

    response.next_response().await.unwrap();
    let _status = response.status().unwrap();
    let _headers = response.headers().unwrap();
    let _header = response.header("content-type".to_string()).unwrap();
    let _body = response.read().await.unwrap();
    let _body = response.read_to_bytes().await.unwrap();
    let _text = response.read_to_string().await.unwrap();
    let _trailers = response.trailers().await.unwrap();
    response.stop(0).await.unwrap();
    let _agent_name = response.agent_name().unwrap();
}

#[allow(dead_code)]
async fn pyo3_server_api_is_exposed(
    endpoint: &dhttp_api::pyo3::Endpoint,
    handler: Py<PyAny>,
    request: &dhttp_api::pyo3::ServerRequest,
    response: &dhttp_api::pyo3::ServerResponse,
    handle: &dhttp_api::pyo3::ServeHandle,
) {
    let _handle = endpoint.serve(handler).unwrap();

    let _method = request.method().unwrap();
    let _uri = request.uri().unwrap();
    let _scheme = request.scheme().unwrap();
    let _authority = request.authority().unwrap();
    let _path = request.path().unwrap();
    let _protocol = request.protocol().unwrap();
    let _headers = request.headers().unwrap();
    let _header = request.header("content-type".to_string()).unwrap();
    let _body = request.read().await.unwrap();
    let _body = request.read_to_bytes().await.unwrap();
    let _text = request.read_to_string().await.unwrap();
    let _trailers = request.trailers().await.unwrap();
    request.stop(0).await.unwrap();
    let _agent_name = request.agent_name().unwrap();
    let _stream_id = request.stream_id().unwrap();

    let _status = response.status().unwrap();
    response.set_status(204).unwrap();
    let _headers = response.headers().unwrap();
    response
        .set_header("content-type".to_string(), "text/plain".to_string())
        .unwrap();
    response.set_body(b"hello".to_vec()).unwrap();
    response.write(b"chunk".to_vec()).await.unwrap();
    response.flush().await.unwrap();
    let _trailers = response.trailers().unwrap();
    response
        .set_trailer("x-trailer".to_string(), "done".to_string())
        .unwrap();
    response
        .set_trailers(vec![("x-trailer".to_string(), "done".to_string())])
        .unwrap();
    response.close().await.unwrap();
    response.cancel(0).await.unwrap();
    let _agent_name = response.agent_name().unwrap();
    let _stream_id = response.stream_id().unwrap();
    response.finish().await.unwrap();

    handle.shutdown().await.unwrap();
    handle.abort();
    let _is_finished = handle.is_finished();
    handle.closed().await.unwrap();
}
