use std::path::PathBuf;

use super::{LoadDhttpHomeError, resolve_global_home_path, resolve_user_home_path};

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
    assert_eq!(
        super::normalize_name(" Alice~ ").as_deref(),
        Some("alice.dhttp.net")
    );
    assert_eq!(
        super::normalize_name("123").as_deref(),
        Some("123.dhttp.net")
    );
    assert!(super::normalize_name("../alice").is_none());
    assert!(super::normalize_name("alice_bob").is_none());
    assert!(super::normalize_name("*.alice").is_none());
    assert!(super::validate_name("alice.dhttp.net").is_ok());
    assert!(super::validate_name("123.dhttp.net").is_ok());
    assert!(super::validate_name("Alice.dhttp.net").is_err());
    assert!(super::validate_name("alice~").is_err());
}

#[test]
fn lookup_names_expand_only_explicit_shorthand() {
    for (input, expected) in [
        (" NAT.Example.CN. ", "nat.example.cn"),
        ("Alice~", "alice.dhttp.net"),
        ("Alice.DHTTP.NET", "alice.dhttp.net"),
        ("Alice", "alice"),
        ("localhost", "localhost"),
    ] {
        assert_eq!(super::normalize_dns_name(input).as_deref(), Some(expected));
    }
    for invalid in [
        "",
        "~",
        "alice~.example.cn",
        "alice_bob",
        "*.example.cn",
        "-alice",
        "alice..smith",
        "alice..",
        "../alice",
    ] {
        assert!(super::normalize_dns_name(invalid).is_none(), "{invalid}");
    }
    let max_length = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61)
    );
    assert!(super::normalize_dns_name(&max_length).is_some());
    assert!(super::normalize_dns_name(&format!("{max_length}a")).is_none());
}

#[test]
fn canonical_dns_name_uses_certserver_lengths_and_numeric_labels() {
    assert!(super::is_valid_dns_name("123.dhttp.net"));
    assert!(!super::is_valid_dns_name("alice_bob.dhttp.net"));
    let max_length = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(51),
    );
    assert_eq!(max_length.len() + super::DHTTP_SUFFIX.len(), 253);
    assert!(super::normalize_name(&max_length).is_some());
    assert!(super::normalize_name(&format!("{max_length}a")).is_none());
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
