use std::{fs, path::PathBuf};

fn api_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn package_versions_match_cargo_release_version() {
    let expected = format!("\"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
    let package_json = fs::read_to_string(api_dir().join("package.json"))
        .expect("package.json should be readable");
    let package_lock = fs::read_to_string(api_dir().join("package-lock.json"))
        .expect("package-lock.json should be readable");

    assert!(
        package_json.contains(&expected),
        "package.json should contain {expected}"
    );
    assert_eq!(
        package_lock.matches(&expected).count(),
        2,
        "package-lock.json should align its root package versions with Cargo"
    );
}
