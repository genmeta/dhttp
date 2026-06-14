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

    async def handler(request):
        await request.writer.reset(0)
        await request.reader.stop(0)

    handle = endpoint.listen_raw(handler)
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
    request: dhttp_api::pyo3::UnresolvedRequest,
    reader: &dhttp_api::pyo3::MessageReader,
    writer: &dhttp_api::pyo3::MessageWriter,
    handle: &dhttp_api::pyo3::ServeHandle,
    handler: Py<PyAny>,
) {
    let _connection = endpoint.connect("example.com".to_string()).await.unwrap();
    let request_from_connection = connection.open_request().await.unwrap();
    let _reader = request_from_connection.reader().unwrap();
    let _writer = request_from_connection.writer().unwrap();

    let _stream_id = request.stream_id();
    let _local = request.local_authority();
    let _remote = request.remote_authority();

    let _headers: Option<Vec<(Vec<u8>, Vec<u8>)>> = reader.read_header().await.unwrap();
    let _chunk: Option<Vec<u8>> = reader.read_data().await.unwrap();
    reader.stop(0).await.unwrap();

    writer
        .write_header(vec![(b":method".to_vec(), b"GET".to_vec())])
        .await
        .unwrap();
    writer.write_data(b"hello".to_vec()).await.unwrap();
    writer.flush().await.unwrap();
    writer.close().await.unwrap();
    writer.reset(0).await.unwrap();

    let _handle = endpoint.listen_raw(handler).unwrap();
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
    let endpoint = std::fs::read_to_string(manifest_dir.join("python/dhttpy/endpoint.py")).unwrap();
    let response = std::fs::read_to_string(manifest_dir.join("python/dhttpy/response.py")).unwrap();

    assert!(endpoint.contains("def _endpoint_options"));
    assert!(endpoint.contains("dns_schemes"));
    assert!(endpoint.contains("bind_patterns"));
    assert!(endpoint.contains("pass either options or keyword configuration, not both"));
    assert!(endpoint.contains("json: Any = None"));
    assert!(endpoint.contains("class QueryParams"));
    assert!(endpoint.contains("def from_query_string"));
    assert!(endpoint.contains("self.query = QueryParams.from_query_string"));
    assert!(endpoint.contains("async def json"));
    assert!(endpoint.contains("self.method = method.upper()"));
    assert!(!endpoint.contains("content: BodyInput = None"));
    assert!(!endpoint.contains("content if content is not None else data"));
    assert!(endpoint.contains("only one of data or json may be provided"));
    assert!(response.contains("def _outbound_header_name"));
    assert!(response.contains("class StreamContent"));
    assert!(response.contains("async def iter_chunked"));
    assert!(response.contains("async def json"));
    assert!(response.contains("def json_response"));
    assert!(response.contains("self.ok = 200 <= self.status < 400"));
    assert!(response.contains("method: str"));
    assert!(response.contains("url: str"));
}

#[test]
fn pyo3_native_surface_uses_raw_message_names_and_hides_stream_pair_model() {
    let source = std::fs::read_to_string(format!("{}/src/pyo3/mod.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("pyo3 module source should be readable");

    for required in [
        "pyclass(name = \"UnresolvedRequest\")",
        "pyclass(name = \"MessageReader\")",
        "pyclass(name = \"MessageWriter\")",
        "pub async fn open_request",
        "pub fn listen_raw",
        "pub async fn read_header",
        "pub async fn read_data",
        "pub async fn write_header",
        "pub async fn write_data",
    ] {
        assert!(
            source.contains(required),
            "missing pyo3 raw symbol {required}"
        );
    }

    for removed in [
        "pyclass(name = \"ReadStream\")",
        "pyclass(name = \"WriteStream\")",
        "pyclass(name = \"IncomingStream\")",
        "pyclass(name = \"StreamPair\")",
        "open_request_stream",
        "listen_streams",
        "send_header",
        "send_data",
        "read_header_frame",
        "read_data_frame_chunk",
    ] {
        assert!(
            !source.contains(removed),
            "removed pyo3 symbol should not appear: {removed}"
        );
    }
}
