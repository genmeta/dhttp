#![cfg(feature = "pyo3")]

use pyo3::prelude::*;
use pyo3::types::PyDict;

#[tokio::test]
async fn pyo3_minimal_endpoint_api_is_constructible() {
    let home = dhttp_api::pyo3::Home::new("/tmp/dhttp-api-pyo3".to_string());
    assert_eq!(home.path(), "/tmp/dhttp-api-pyo3");
    let identity_home = home.identity_home("reimu.pilot".to_string()).unwrap();
    assert_eq!(identity_home.name(), "reimu.pilot");
    assert_eq!(
        identity_home.path(),
        "/tmp/dhttp-api-pyo3/reimu.pilot".to_string()
    );
    assert!(
        !home
            .identity_exists("missing.pilot".to_string())
            .await
            .unwrap()
    );

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
    request
        .headers(vec![(
            "user-agent".to_string(),
            "dhttp-api-test".to_string(),
        )])
        .unwrap();
    request
        .set_headers(vec![("accept".to_string(), "application/json".to_string())])
        .unwrap();
    request.body(b"hello".to_vec()).unwrap();
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

#[test]
fn pyo3_async_home_methods_work_from_python_asyncio_without_external_tokio_runtime() {
    Python::initialize();
    Python::attach(|py| {
        let module = PyModule::new(py, "dhttp_api").unwrap();
        dhttp_api::pyo3::dhttp_api(&module).unwrap();
        let path = std::env::temp_dir()
            .join(format!("dhttp-api-pyo3-asyncio-{}", std::process::id()))
            .display()
            .to_string();
        let locals = PyDict::new(py);
        locals.set_item("dhttp_api", module.as_any()).unwrap();
        locals.set_item("path", path).unwrap();

        py.run(
            c"
import asyncio

async def main():
    home = dhttp_api.Home(path)
    assert await home.identity_exists('missing.pilot') is False
    endpoint = await dhttp_api.Endpoint.create(None)

    async def handler(_request, response):
        response.set_status(204)

    handle = endpoint.serve(handler)
    handle.abort()
    await handle.closed()

asyncio.run(main())
",
            Some(&locals),
            Some(&locals),
        )
        .unwrap();
    });
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

#[allow(dead_code)]
async fn pyo3_home_identity_api_is_exposed(
    home: &dhttp_api::pyo3::Home,
    identity_home: &dhttp_api::pyo3::IdentityHome,
    identity: &dhttp_api::pyo3::Identity,
) {
    let _identity_home =
        dhttp_api::pyo3::IdentityHome::new("/tmp/reimu.pilot".to_string()).unwrap();
    let _identity_home = home.load_identity("reimu.pilot".to_string()).await.unwrap();
    let _identities = home.identities().await.unwrap();
    let _identity = identity_home.identity().await.unwrap();
    let _certs = identity.cert_chain_der();
    let _public_key = identity.public_key_der();
}
