#![cfg(feature = "napi")]

use napi::bindgen_prelude::Buffer;
use napi::bindgen_prelude::{Either, FnArgs, Function, Promise};

type ServerHandlerArgs = FnArgs<(
    dhttp_api::napi::ServerRequest,
    dhttp_api::napi::ServerResponse,
)>;
type ServerHandlerResult = Either<Promise<()>, ()>;

#[tokio::test]
async fn napi_minimal_endpoint_api_is_constructible() {
    let config = dhttp_api::napi::Config::new("/tmp/dhttp-api-napi".to_string());
    assert_eq!(config.path(), "/tmp/dhttp-api-napi");
    let identity_config = config.identity_config("reimu.pilot".to_string()).unwrap();
    assert_eq!(identity_config.name(), "reimu.pilot");
    assert_eq!(
        identity_config.path(),
        "/tmp/dhttp-api-napi/reimu.pilot".to_string()
    );
    assert!(
        !config
            .identity_exists("missing.pilot".to_string())
            .await
            .unwrap()
    );

    let mut options = dhttp_api::napi::EndpointOptions::new();
    options.add_bind_pattern("*".to_string()).unwrap();
    assert_eq!(options.bind_patterns(), vec!["iface://*".to_string()]);

    let endpoint = dhttp_api::napi::Endpoint::create(None).await.unwrap();
    assert!(endpoint.identity().is_none());

    let request = endpoint.request();
    request.set_method("POST".to_string()).unwrap();
    request
        .set_uri("https://example.com/api".to_string())
        .unwrap();
    request
        .header("content-type".to_string(), "text/plain".to_string())
        .unwrap();
    request
        .headers(vec![(
            "user-agent".to_string(),
            "dhttp-api-test".to_string(),
        )])
        .unwrap();
    request
        .set_headers(vec![("accept".to_string(), "application/json".to_string())])
        .unwrap();
    request.body(Buffer::from(b"hello".to_vec())).unwrap();
    request
        .trailer("x-trailer".to_string(), "done".to_string())
        .unwrap();
    request
        .trailers(vec![("x-checksum".to_string(), "ok".to_string())])
        .unwrap();
    request
        .set_trailers(vec![("x-finished".to_string(), "true".to_string())])
        .unwrap();

    let _get = endpoint.get("https://example.com/".to_string()).unwrap();
    let _post = endpoint.post("https://example.com/".to_string()).unwrap();
}

#[allow(dead_code)]
async fn napi_client_response_api_is_exposed(
    request: dhttp_api::napi::ClientRequest,
    response: &dhttp_api::napi::ClientResponse,
) {
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
async fn napi_server_api_is_exposed<'env>(
    endpoint: &dhttp_api::napi::Endpoint,
    handler: Function<'env, ServerHandlerArgs, ServerHandlerResult>,
    request: &dhttp_api::napi::ServerRequest,
    response: &dhttp_api::napi::ServerResponse,
    handle: &dhttp_api::napi::ServeHandle,
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
    response.set_body(Buffer::from(b"hello".to_vec())).unwrap();
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

#[allow(dead_code)]
async fn napi_config_identity_api_is_exposed(
    config: &dhttp_api::napi::Config,
    identity_config: &dhttp_api::napi::IdentityConfig,
    identity: &dhttp_api::napi::Identity,
) {
    let _identity_config =
        dhttp_api::napi::IdentityConfig::from_path("/tmp/reimu.pilot".to_string()).unwrap();
    let _identity_config = config
        .load_identity("reimu.pilot".to_string())
        .await
        .unwrap();
    let _identities = config.identities().await.unwrap();
    let _identity = identity_config.identity().await.unwrap();
    let _certs = identity.cert_chain_der();
    let _public_key = identity.public_key_der();
}
