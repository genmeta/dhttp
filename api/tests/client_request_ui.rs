#[test]
fn old_public_request_response_ui_tests_are_removed() {
    let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ui");
    if !ui_dir.exists() {
        return;
    }

    assert!(
        std::fs::read_dir(ui_dir)
            .unwrap()
            .filter_map(Result::ok)
            .all(
                |entry| !entry.file_name().to_string_lossy().contains("_request")
                    && !entry.file_name().to_string_lossy().contains("_response")
            )
    );
}
