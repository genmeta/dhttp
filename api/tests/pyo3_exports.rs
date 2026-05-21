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
}
