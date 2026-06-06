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

    assert!(root_dts.contains("export type DnsScheme = \"mdns\" | \"http\" | \"h3\" | \"system\";"));
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
    assert!(raw_dts
        .contains("localAuthority(): Promise<import(\"@genmeta/dhttp\").LocalAuthority | null>"));
    assert!(raw_dts
        .contains("remoteAuthority(): Promise<import(\"@genmeta/dhttp\").RemoteAuthority | null>"));
    assert!(!raw_dts.contains("get connection"));
    assert!(!raw_dts.contains("ReadStream"));
    assert!(!raw_dts.contains("WriteStream"));
    assert!(!raw_dts.contains("IncomingStream"));
    assert!(!raw_dts.contains("StreamPair"));
}
