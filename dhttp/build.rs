use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );

    // DHTTP ecosystem root trust anchor. The current certificate is the
    // transitional genmeta root; it is expected to be replaced by the dhttp.net
    // root when the ecosystem switches domains.
    let default_path = manifest_dir.join("../keychain/root.crt");
    let src = std::env::var_os("ROOT_CA").map_or(default_path, PathBuf::from);

    let dest = out_dir.join("root.crt");
    std::fs::copy(&src, &dest).unwrap_or_else(|error| {
        panic!(
            "failed to copy DHTTP root CA from {} to {}: {error}",
            src.display(),
            dest.display()
        )
    });

    println!("cargo::rerun-if-env-changed=ROOT_CA");
    println!("cargo::rerun-if-changed={}", src.display());
}
