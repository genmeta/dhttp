#![cfg(feature = "napi")]

use napi::bindgen_prelude::{Buffer, Either, FnArgs, Function, Promise};

type RawHandlerArgs = FnArgs<(dhttp_api::napi::UnresolvedRequest,)>;
type RawHandlerResult = Either<Promise<()>, ()>;

#[tokio::test]
async fn napi_minimal_endpoint_api_is_constructible() {
    let home = dhttp_api::napi::DhttpHome::new("/tmp/dhttp-api-napi".to_string());
    assert_eq!(home.path(), "/tmp/dhttp-api-napi");
    let profile = home.identity_profile("reimu.pilot".to_string()).unwrap();
    assert_eq!(profile.name(), "reimu.pilot");
    assert_eq!(
        profile.path(),
        "/tmp/dhttp-api-napi/reimu.pilot".to_string()
    );
    assert!(
        !home
            .identity_profile_exists("missing.pilot".to_string())
            .await
            .unwrap()
    );

    let mut options = dhttp_api::napi::EndpointOptions::new();
    options.add_bind_pattern("*".to_string()).unwrap();
    assert_eq!(options.bind_patterns(), vec!["iface://*".to_string()]);

    let endpoint = dhttp_api::napi::Endpoint::create(None).await.unwrap();
    assert!(endpoint.identity().is_none());
}

#[test]
fn napi_header_field_preserves_bytes_at_type_boundary() {
    let field = dhttp_api::napi::HeaderField {
        name: Buffer::from(b"x-bin".to_vec()),
        value: Buffer::from(b"\xff".to_vec()),
    };

    assert_eq!(field.name.as_ref(), b"x-bin");
    assert_eq!(field.value.as_ref(), b"\xff");
}

#[test]
fn napi_stream_wrapper_types_are_send() {
    fn assert_send<T: Send>() {}

    assert_send::<dhttp_api::napi::Connection>();
    assert_send::<dhttp_api::napi::UnresolvedRequest>();
    assert_send::<dhttp_api::napi::MessageReader>();
    assert_send::<dhttp_api::napi::MessageWriter>();
}

#[allow(dead_code)]
async fn napi_raw_primitive_api_is_exposed(
    endpoint: &dhttp_api::napi::Endpoint,
    connection: &dhttp_api::napi::Connection,
    request: dhttp_api::napi::UnresolvedRequest,
    reader: &dhttp_api::napi::MessageReader,
    writer: &dhttp_api::napi::MessageWriter,
) {
    let _connection = endpoint.connect("example.com".to_string()).await.unwrap();
    let _request = connection.open_request().await.unwrap();

    let _stream_id = request.stream_id();
    let _reader = request.reader().unwrap();
    let _writer = request.writer().unwrap();
    let _local = request.local_authority();
    let _remote = request.remote_authority();

    let _headers: Option<Vec<dhttp_api::napi::HeaderField>> = reader.read_header().await.unwrap();
    let _chunk: Option<Vec<u8>> = reader.read_data().await.unwrap();
    reader.stop(0).await.unwrap();

    writer
        .write_header(vec![dhttp_api::napi::HeaderField {
            name: Buffer::from(b":method".to_vec()),
            value: Buffer::from(b"GET".to_vec()),
        }])
        .await
        .unwrap();
    writer
        .write_data(Buffer::from(b"hello".to_vec()))
        .await
        .unwrap();
    writer.flush().await.unwrap();
    writer.close().await.unwrap();
    writer.reset(0).await.unwrap();
}

#[allow(dead_code)]
async fn napi_raw_server_api_is_exposed<'env>(
    endpoint: &dhttp_api::napi::Endpoint,
    handler: Function<'env, RawHandlerArgs, RawHandlerResult>,
    handle: &dhttp_api::napi::ServeHandle,
) {
    let _handle = endpoint.listen_raw(handler).unwrap();

    handle.shutdown().await.unwrap();
    handle.abort().unwrap();
    let _is_finished = handle.is_finished();
    handle.closed().await.unwrap();
}

#[allow(dead_code)]
async fn napi_home_identity_api_is_exposed(
    home: &dhttp_api::napi::DhttpHome,
    profile: &dhttp_api::napi::IdentityProfile,
    identity: &dhttp_api::napi::Identity,
) {
    let _profile =
        dhttp_api::napi::IdentityProfile::from_path("/tmp/reimu.pilot".to_string()).unwrap();
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
fn napi_public_surface_has_no_legacy_request_response_wrappers() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        manifest_dir.join("src/napi/mod.rs"),
        manifest_dir.join("js/index.js"),
        manifest_dir.join("js/index.d.ts"),
    ]
    .into_iter()
    .map(std::fs::read_to_string)
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
    .join("\n");

    for forbidden in [
        concat!("Client", "Request"),
        concat!("Client", "Response"),
        concat!("Server", "Request"),
        concat!("Server", "Response"),
        concat!("Raw", "Request"),
        concat!("Raw", "Response"),
        concat!("fetch", "Raw"),
        concat!("request", "Raw"),
        concat!("request", "_raw"),
    ] {
        assert!(
            !sources.contains(forbidden),
            "NAPI source must not expose legacy public name {forbidden}"
        );
    }
}

#[test]
fn node_wrapper_rejects_missing_pseudo_headers_instead_of_defaulting() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("js/index.js"),
    )
    .unwrap();

    assert!(source.contains("response header frame is missing"));
    assert!(source.contains("response status pseudo-header is missing"));
    assert!(source.contains("request pseudo-headers are missing"));
    assert!(!source.contains("?? 'GET'"));
    assert!(!source.contains("?? 'https'"));
    assert!(!source.contains("?? 'localhost'"));
}

#[test]
fn node_wrapper_exports_match_type_declarations_and_hide_native_entry() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();
    let dts = std::fs::read_to_string(manifest_dir.join("js/index.d.ts")).unwrap();
    let package_json = std::fs::read_to_string(manifest_dir.join("package.json")).unwrap();

    assert!(js.contains("Identity,"));
    assert!(!js.contains("Identity: native.Identity"));
    assert!(js.contains("ServeHandle: native.ServeHandle"));
    assert!(js.contains("function endpointOptionsFrom"));
    assert!(dts.contains("interface EndpointOptions"));
    assert!(dts.contains("dnsSchemes?: Iterable<DnsScheme>"));
    assert!(dts.contains("bindPatterns?: Iterable<string>"));
    assert!(dts.contains("static create(options?: EndpointOptions | null)"));
    assert!(package_json.contains("\"exports\""));
    assert!(package_json.contains("\"./js/index.js\""));
    assert!(!package_json.contains("\"./index.js\""));
}

#[test]
fn node_wrapper_cleans_up_raw_streams_on_server_errors_and_reset() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("js/index.js"),
    )
    .unwrap();

    assert!(source.contains("activePull"));
    assert!(source.contains("requestStop"));
    assert!(source.contains("return { stream, stop: requestStop }"));
    assert!(source.contains("await requestState.stopBody()"));
    assert!(source.contains("await writer.reset(0)"));
}

#[test]
fn napi_read_stream_stop_can_interrupt_in_flight_read() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let napi_source = std::fs::read_to_string(manifest_dir.join("src/napi/mod.rs")).unwrap();
    let js_source = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(napi_source.contains("struct ActiveRead"));
    assert!(napi_source.contains("active: Option<ActiveRead>"));
    assert!(napi_source.contains("stop_requested: Option<u64>"));
    assert!(napi_source.contains("struct ActiveReadCleanup"));
    assert!(napi_source.contains("tokio::select!"));
    assert!(!js_source.contains("if (activePull != null) {\n      return;\n    }"));
}

#[test]
fn napi_node_raw_surface_uses_message_and_unresolved_names() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/napi/mod.rs"),
    )
    .unwrap();

    assert!(source.contains("js_name = \"MessageReader\""));
    assert!(source.contains("js_name = \"MessageWriter\""));
    assert!(source.contains("js_name = \"UnresolvedRequest\""));
    assert!(source.contains("pub async fn open_request"));
    assert!(source.contains("pub fn listen_raw"));
    assert!(source.contains("pub async fn read_header"));
    assert!(source.contains("pub async fn read_data"));
    assert!(source.contains("pub async fn write_header"));
    assert!(source.contains("pub async fn write_data"));
    assert!(!source.contains("js_name = \"StreamPair\""));
    assert!(!source.contains("js_name = \"IncomingStream\""));
    assert!(!source.contains("js_name = \"ReadStream\""));
    assert!(!source.contains("js_name = \"WriteStream\""));
    assert!(!source.contains("pub async fn send_header"));
    assert!(!source.contains("pub async fn send_data"));
}

#[test]
fn napi_internal_stream_calls_use_read_write_vocabulary() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(manifest_dir.join("src/napi/mod.rs")).unwrap();

    assert!(source.contains("inner.read_header"));
    assert!(source.contains("inner.read_data"));
    assert!(source.contains("inner.write_header"));
    assert!(source.contains("inner.write_data"));
    assert!(!source.contains("inner.send_header"));
    assert!(!source.contains("inner.send_data"));
}
