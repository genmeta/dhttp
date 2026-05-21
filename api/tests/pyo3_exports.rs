#![cfg(feature = "pyo3")]

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
