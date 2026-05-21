#![cfg(feature = "napi")]

#[tokio::test]
async fn napi_minimal_endpoint_api_is_constructible() {
    let home = dhttp_api::napi::Home::new("/tmp/dhttp-api-napi".to_string());
    assert_eq!(home.path(), "/tmp/dhttp-api-napi");

    let mut options = dhttp_api::napi::EndpointOptions::new();
    options.add_bind_pattern("*".to_string()).unwrap();
    assert_eq!(options.bind_patterns(), vec!["iface://*".to_string()]);

    let endpoint = dhttp_api::napi::Endpoint::create(None).await.unwrap();
    assert!(endpoint.identity().is_none());
}
