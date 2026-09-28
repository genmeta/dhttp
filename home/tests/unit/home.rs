use std::path::PathBuf;

use super::{LoadDhttpHomeError, resolve_global_home_path, resolve_user_home_path};

#[test]
fn request_uri_expands_shorthand_and_identifies_remote() {
    let (uri, remote) = super::resolve_request_uri(
        "alice.dhttp.net",
        "https://bob~/upload?q=1".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(uri.to_string(), "https://bob.dhttp.net/upload?q=1");
    assert_eq!(remote, "bob.dhttp.net");

    let (uri, remote) =
        super::resolve_request_uri("alice.dhttp.net", "https://~/self".parse().unwrap()).unwrap();
    assert_eq!(uri.to_string(), "https://alice.dhttp.net/self");
    assert_eq!(remote, "alice.dhttp.net");

    let (uri, remote) =
        super::resolve_request_uri("alice.dhttp.net", "https://Bob/x".parse().unwrap()).unwrap();
    assert_eq!(uri.to_string(), "https://Bob/x");
    assert_eq!(remote, "bob.dhttp.net");
}

#[test]
fn request_uri_rejects_unsupported_scheme_and_missing_authority() {
    use super::ResolveRequestUriError;

    let error =
        super::resolve_request_uri("alice.dhttp.net", "ftp://bob~/x".parse().unwrap()).unwrap_err();
    assert!(matches!(error, ResolveRequestUriError::UnsupportedScheme));

    let error = super::resolve_request_uri("alice.dhttp.net", "/x".parse().unwrap()).unwrap_err();
    assert!(matches!(
        error,
        ResolveRequestUriError::MissingRemoteAuthority
    ));

    let error =
        super::resolve_request_uri("alice.dhttp.net", "https://bad_name/x".parse().unwrap())
            .unwrap_err();
    assert!(matches!(
        error,
        ResolveRequestUriError::InvalidRemoteName { name } if name == "bad_name"
    ));
}

#[test]
fn normalizes_identity_names() {
    assert_eq!(
        super::normalize_name(" Alice ").as_deref(),
        Some("alice.dhttp.net")
    );
    assert_eq!(
        super::normalize_name("Alice.DHTTP.NET").as_deref(),
        Some("alice.dhttp.net")
    );
    assert!(super::normalize_name("../alice").is_none());
    assert!(super::validate_name("alice.dhttp.net").is_ok());
    assert!(super::validate_name("Alice.dhttp.net").is_err());
}

#[test]
fn user_scope_path_prefers_runtime_home_env() {
    let path = resolve_user_home_path(
        Some(PathBuf::from("/runtime/dhttp-home")),
        Some(PathBuf::from("/home/reimu")),
    )
    .expect("user path should resolve");

    assert_eq!(path, PathBuf::from("/runtime/dhttp-home"));
}

#[test]
fn user_scope_path_falls_back_to_user_home_dir() {
    let path = resolve_user_home_path(None, Some(PathBuf::from("/home/reimu")))
        .expect("user path should resolve");

    assert_eq!(path, PathBuf::from("/home/reimu/.dhttp"));
}

#[test]
fn global_scope_path_prefers_runtime_env_over_compile_time_and_default() {
    let path = resolve_global_home_path(
        Some(PathBuf::from("/runtime/global")),
        Some("/compiled/global"),
        Some("/etc/dhttp"),
    )
    .expect("global path should resolve");

    assert_eq!(path, PathBuf::from("/runtime/global"));
}

#[test]
fn global_scope_path_uses_compile_time_home_when_runtime_is_missing() {
    let path = resolve_global_home_path(None, Some("/compiled/global"), Some("/etc/dhttp"))
        .expect("global path should resolve");

    assert_eq!(path, PathBuf::from("/compiled/global"));
}

#[test]
fn global_scope_path_uses_platform_default_when_overrides_are_missing() {
    let path = resolve_global_home_path(None, None, Some("/etc/dhttp"))
        .expect("global path should resolve");

    assert_eq!(path, PathBuf::from("/etc/dhttp"));
}

#[test]
fn global_scope_path_errors_when_no_source_is_available() {
    let error = resolve_global_home_path(None, None, None)
        .expect_err("missing global path sources must fail");

    assert!(matches!(
        error,
        LoadDhttpHomeError::GlobalHomeNotConfigured {}
    ));
}
