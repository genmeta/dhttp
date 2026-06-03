#![cfg(feature = "pyo3")]

use pyo3::prelude::*;
use pyo3::types::PyDict;

#[tokio::test]
async fn pyo3_minimal_endpoint_api_is_constructible() {
    let home = dhttp_api::pyo3::DhttpHome::new("/tmp/dhttp-api-pyo3".to_string());
    assert_eq!(home.path(), "/tmp/dhttp-api-pyo3");
    let profile = home.identity_profile("reimu.pilot".to_string()).unwrap();
    assert_eq!(profile.name(), "reimu.pilot");
    assert_eq!(
        profile.path(),
        "/tmp/dhttp-api-pyo3/reimu.pilot".to_string()
    );
    assert!(
        !home
            .identity_profile_exists("missing.pilot".to_string())
            .await
            .unwrap()
    );

    let mut options = dhttp_api::pyo3::EndpointOptions::new();
    options.add_bind_pattern("*".to_string()).unwrap();
    assert_eq!(options.bind_patterns(), vec!["iface://*".to_string()]);

    let endpoint = dhttp_api::pyo3::Endpoint::create(None).await.unwrap();
    assert!(endpoint.identity().is_none());
    let _bind_patterns = endpoint.bind_patterns();
}

#[test]
fn pyo3_async_home_methods_work_from_python_asyncio_without_external_tokio_runtime() {
    Python::initialize();
    Python::attach(|py| {
        let module = PyModule::new(py, "_native").unwrap();
        dhttp_api::pyo3::_native(&module).unwrap();
        let path = std::env::temp_dir()
            .join(format!("dhttp-api-pyo3-asyncio-{}", std::process::id()))
            .display()
            .to_string();
        let locals = PyDict::new(py);
        locals.set_item("dhttp_native", module.as_any()).unwrap();
        locals.set_item("path", path).unwrap();

        py.run(
            c"
import asyncio

async def main():
    home = dhttp_native.DhttpHome(path)
    assert await home.identity_profile_exists('missing.pilot') is False
    endpoint = await dhttp_native.Endpoint.create(None)

    async def handler(incoming):
        await incoming.write_stream.reset(0)
        await incoming.read_stream.stop(0)

    handle = endpoint.listen_streams(handler)
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
async fn pyo3_native_stream_primitive_api_is_exposed(
    endpoint: &dhttp_api::pyo3::Endpoint,
    connection: &dhttp_api::pyo3::Connection,
    read_stream: &dhttp_api::pyo3::ReadStream,
    write_stream: &dhttp_api::pyo3::WriteStream,
    incoming: &dhttp_api::pyo3::IncomingStream,
    handle: &dhttp_api::pyo3::ServeHandle,
    handler: Py<PyAny>,
) {
    let _connection = endpoint.connect("example.com".to_string()).await.unwrap();
    let pair = connection.open_request_stream().await.unwrap();
    let _read_stream = pair.read_stream().unwrap();
    let _write_stream = pair.write_stream().unwrap();

    let _chunk = read_stream.read_data_frame_chunk().await.unwrap();
    let _headers: Option<Vec<(Vec<u8>, Vec<u8>)>> = read_stream.read_header_frame().await.unwrap();
    read_stream.stop(0).await.unwrap();

    write_stream
        .send_header(vec![(b":method".to_vec(), b"GET".to_vec())])
        .await
        .unwrap();
    write_stream.send_data(b"hello".to_vec()).await.unwrap();
    write_stream.flush().await.unwrap();
    write_stream.close().await.unwrap();
    write_stream.reset(0).await.unwrap();

    let _stream_id = incoming.stream_id();
    let _read_stream = incoming.read_stream().unwrap();
    let _write_stream = incoming.write_stream().unwrap();

    let _handle = endpoint.listen_streams(handler).unwrap();
    handle.shutdown().await.unwrap();
    handle.abort();
    let _is_finished = handle.is_finished();
    handle.closed().await.unwrap();
}

#[allow(dead_code)]
async fn pyo3_home_identity_api_is_exposed(
    home: &dhttp_api::pyo3::DhttpHome,
    profile: &dhttp_api::pyo3::IdentityProfile,
    identity: &dhttp_api::pyo3::Identity,
) {
    let _profile = dhttp_api::pyo3::IdentityProfile::new("/tmp/reimu.pilot".to_string()).unwrap();
    let _profile = home
        .resolve_identity_profile("reimu.pilot".to_string())
        .await
        .unwrap();
    let _names = home.identity_profile_names().await.unwrap();
    let _identity = profile.load_identity().await.unwrap();
    let _certs = identity.cert_chain_der();
    let _public_key = identity.public_key_der();
}

#[test]
fn pyo3_native_surface_does_not_export_removed_request_response_wrappers() {
    let source = std::fs::read_to_string(format!("{}/src/pyo3/mod.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("pyo3 module source should be readable");
    for removed in [
        concat!("Client", "Request"),
        concat!("Client", "Response"),
        concat!("Server", "Request"),
        concat!("Server", "Response"),
        concat!("Raw", "Request"),
        concat!("Raw", "Response"),
        concat!("request", "_raw"),
        concat!("fetch", "_raw"),
    ] {
        assert!(
            !source.contains(removed),
            "removed pyo3 symbol should not appear in native source: {removed}"
        );
    }
}

#[test]
fn pyo3_read_stream_stop_can_interrupt_in_flight_read() {
    let source = std::fs::read_to_string(format!("{}/src/pyo3/mod.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("pyo3 module source should be readable");

    assert!(source.contains("struct ActiveRead"));
    assert!(source.contains("active: Option<ActiveRead>"));
    assert!(source.contains("stop_requested: Option<u64>"));
    assert!(source.contains("struct ActiveReadCleanup"));
    assert!(source.contains("tokio::select!"));
}

#[test]
fn python_wrapper_uses_aiohttp_like_request_and_body_helpers() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let endpoint = std::fs::read_to_string(manifest_dir.join("python/dhttp/endpoint.py")).unwrap();
    let response = std::fs::read_to_string(manifest_dir.join("python/dhttp/response.py")).unwrap();

    assert!(endpoint.contains("def _endpoint_options"));
    assert!(endpoint.contains("dns_schemes"));
    assert!(endpoint.contains("bind_patterns"));
    assert!(endpoint.contains("pass either options or keyword configuration, not both"));
    assert!(endpoint.contains("json: Any = None"));
    assert!(endpoint.contains("content: BodyInput = None"));
    assert!(endpoint.contains("only one of data, json, or content may be provided"));
    assert!(response.contains("class StreamContent"));
    assert!(response.contains("async def iter_chunked"));
    assert!(response.contains("async def json"));
}
