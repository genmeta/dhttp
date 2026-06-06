#[test]
fn package_declares_node_engine_and_dual_entrypoints() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let package_json = std::fs::read_to_string(manifest_dir.join("package.json")).unwrap();

    assert!(package_json.contains("\"engines\""));
    assert!(package_json.contains("\"node\": \">=22.17.0\""));
    assert!(package_json.contains("\".\""));
    assert!(package_json.contains("\"./raw\""));
    assert!(package_json.contains("\"import\": \"./js/index.mjs\""));
    assert!(package_json.contains("\"require\": \"./js/index.js\""));
    assert!(package_json.contains("\"types\": \"./js/index.d.ts\""));
    assert!(package_json.contains("\"import\": \"./js/raw.mjs\""));
    assert!(package_json.contains("\"require\": \"./js/raw.js\""));
    assert!(package_json.contains("\"types\": \"./js/raw.d.ts\""));
}

#[test]
fn root_and_raw_type_declarations_are_separated() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root_dts = std::fs::read_to_string(manifest_dir.join("js/index.d.ts")).unwrap();
    let raw_dts = std::fs::read_to_string(manifest_dir.join("js/raw.d.ts")).unwrap();

    assert!(
        root_dts.contains("export type DnsScheme = \"mdns\" | \"http\" | \"h3\" | \"system\";")
    );
    assert!(root_dts.contains("export interface EndpointOptions"));
    assert!(root_dts.contains("export interface Service extends RawHandler"));
    assert!(root_dts.contains("export const Service"));
    assert!(root_dts.contains("new (): Service"));
    assert!(root_dts.contains("from(handler: FetchHandler): Service"));
    assert!(root_dts.contains("export interface LocalAuthority"));
    assert!(root_dts.contains("export interface RemoteAuthority"));
    assert!(!root_dts.contains("export class EndpointOptions"));
    assert!(!root_dts.contains("export class LocalAuthority"));
    assert!(!root_dts.contains("export class RemoteAuthority"));
    assert!(!root_dts.contains("export class UnresolvedRequest"));
    assert!(!root_dts.contains("export class MessageReader"));
    assert!(!root_dts.contains("export class MessageWriter"));

    assert!(raw_dts.contains("export class Connection"));
    assert!(raw_dts.contains("openRequest(): Promise<UnresolvedRequest>"));
    assert!(raw_dts.contains("export class UnresolvedRequest"));
    assert!(raw_dts.contains("get reader(): MessageReader"));
    assert!(raw_dts.contains("get writer(): MessageWriter"));
    assert!(
        raw_dts.contains(
            "localAuthority(): Promise<import(\"@genmeta/dhttp\").LocalAuthority | null>"
        )
    );
    assert!(
        raw_dts.contains(
            "remoteAuthority(): Promise<import(\"@genmeta/dhttp\").RemoteAuthority | null>"
        )
    );
    assert!(!raw_dts.contains("get connection"));
    assert!(!raw_dts.contains("ReadStream"));
    assert!(!raw_dts.contains("WriteStream"));
    assert!(!raw_dts.contains("IncomingStream"));
    assert!(!raw_dts.contains("StreamPair"));
}

#[test]
fn root_js_facade_exposes_service_and_hides_raw_classes() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(js.contains("function Service()"));
    assert!(js.contains("if (!new.target)"));
    assert!(js.contains("Service.from = function"));
    assert!(js.contains("function createService"));
    assert!(js.contains("handler returned a Response"));
    assert!(js.contains("listen(handler)"));
    assert!(js.contains("return this.#inner.listenRaw"));
    assert!(js.contains("Service,"));
    assert!(!js.contains("EndpointOptions: native.EndpointOptions"));
    assert!(!js.contains("LocalAuthority: native.LocalAuthority"));
    assert!(!js.contains("RemoteAuthority: native.RemoteAuthority"));
    assert!(!js.contains("listenStreams"));
}

#[test]
fn root_js_uses_raw_message_method_names() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(js.contains("readHeader()"));
    assert!(js.contains("readData()"));
    assert!(js.contains("writeHeader("));
    assert!(js.contains("writeData("));
    assert!(!js.contains("readHeaderFrame"));
    assert!(!js.contains("readDataFrameChunk"));
    assert!(!js.contains("sendHeader"));
    assert!(!js.contains("sendData"));
}

#[test]
fn js_facade_uses_plain_options_and_uint8array_normalization() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();
    let dts = std::fs::read_to_string(manifest_dir.join("js/index.d.ts")).unwrap();

    assert!(js.contains("function endpointOptionsFrom(options)"));
    assert!(!js.contains("options instanceof native.EndpointOptions"));
    assert!(js.contains("function bytes(value)"));
    assert!(js.contains("new Uint8Array(value)"));
    assert!(dts.contains("certChainDer(): Uint8Array[]"));
    assert!(dts.contains("publicKeyDer(): Uint8Array"));
    assert!(dts.contains("sign(data: Uint8Array): Uint8Array"));
    assert!(dts.contains("verify(data: Uint8Array, signature: Uint8Array): boolean"));
}

#[test]
fn raw_entrypoint_exports_only_raw_primitives() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raw_js = std::fs::read_to_string(manifest_dir.join("js/raw.js")).unwrap();

    assert!(raw_js.contains("Connection: native.Connection"));
    assert!(raw_js.contains("UnresolvedRequest: native.UnresolvedRequest"));
    assert!(raw_js.contains("MessageReader: native.MessageReader"));
    assert!(raw_js.contains("MessageWriter: native.MessageWriter"));
    assert!(!raw_js.contains("EndpointOptions"));
    assert!(!raw_js.contains("Identity"));
    assert!(!raw_js.contains("DhttpHome"));
}

#[test]
fn js_fetch_validates_request_init_policy_fields() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(js.contains("const CACHE_MODES"));
    assert!(js.contains("const CREDENTIALS_MODES"));
    assert!(js.contains("const REQUEST_MODES"));
    assert!(js.contains("const REDIRECT_MODES"));
    assert!(js.contains("validateRequestInit"));
    assert!(js.contains("unsupported integrity"));
    assert!(js.contains("window must be null"));
    assert!(js.contains("duplex must be \"half\""));
    assert!(js.contains("rejectPseudoHeaders(request.headers, 'request')"));
    assert!(js.contains("rejectPseudoHeaders(response.headers, 'response')"));
}

#[test]
fn js_fetch_implements_concurrent_upload_abort_and_redirect_helpers() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(js.contains("function abortError"));
    assert!(js.contains("function raceHeaderAndUpload"));
    assert!(js.contains("const uploadPromise"));
    assert!(js.contains("await writer.writeHeader(requestHeaderFields(request))"));
    assert!(js.contains("reader.readHeader()"));
    assert!(js.contains("signal.addEventListener('abort'"));
    assert!(js.contains("response body aborted"));
    assert!(js.contains("function shouldHaveBody"));
    assert!(js.contains("await stopReadStream(reader)"));
    assert!(js.contains("MAX_REDIRECTS"));
    assert!(js.contains("function redirectRequest"));
    assert!(js.contains("redirect === 'manual'"));
    assert!(js.contains("redirect === 'error'"));
}

#[test]
fn js_fetch_body_stream_tracks_upload_errors_without_poll_race() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js = std::fs::read_to_string(manifest_dir.join("js/index.js")).unwrap();

    assert!(js.contains("let uploadError = null"));
    assert!(js.contains("uploadPromise.then("));
    assert!(js.contains("uploadError = error"));
    assert!(!js.contains("Promise.resolve(null)"));
}
