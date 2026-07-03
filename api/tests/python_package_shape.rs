#[test]
fn pyproject_and_python_package_use_dhttpy() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pyproject = std::fs::read_to_string(manifest_dir.join("pyproject.toml")).unwrap();

    assert!(pyproject.contains("name = \"dhttpy\""));
    assert!(pyproject.contains("module-name = \"dhttpy._native\""));
    assert!(manifest_dir.join("python/dhttpy/__init__.py").exists());
    assert!(manifest_dir.join("python/dhttpy/endpoint.py").exists());
    assert!(manifest_dir.join("python/dhttpy/response.py").exists());
}

#[test]
fn publish_workflows_use_dhttpy_and_supported_macos_runner() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap();
    let publish_pypi =
        std::fs::read_to_string(repo_root.join(".github/workflows/publish-pypi.yml")).unwrap();
    let publish_npm =
        std::fs::read_to_string(repo_root.join(".github/workflows/publish-npm.yml")).unwrap();

    assert!(publish_pypi.contains("import dhttpy"));
    assert!(publish_pypi.contains("import dhttpy._native"));
    assert!(publish_pypi.contains("release_channel=preview"));
    assert!(publish_npm.contains("- os: macos-15-intel"));
    assert!(publish_npm.contains("--tag \"$NPM_DIST_TAG\""));
    assert!(publish_npm.contains("dist_tag=\"preview\""));
    assert!(!publish_npm.contains("- os: macos-13"));
}
