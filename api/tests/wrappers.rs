use std::path::{Path, PathBuf};

use dhttp::name::DhttpName;
use dhttp_api::{
    error::DhttpError,
    home::{Home, IdentityHome},
    identity::Identity,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn http_boundary_aliases_are_public() {
    let headers: dhttp_api::http::HeaderPairs =
        vec![("content-type".to_string(), "text/plain".to_string())];
    let body: dhttp_api::http::Body = b"hello".to_vec();
    let method: dhttp_api::http::Method = "GET".to_string();
    let uri: dhttp_api::http::Uri = "https://example.com/".to_string();
    let authority: dhttp_api::http::Authority = "example.com".to_string();
    let status: dhttp_api::http::Status = 200;

    assert_eq!(headers.len(), 1);
    assert_eq!(body, b"hello");
    assert_eq!(method, "GET");
    assert_eq!(uri, "https://example.com/");
    assert_eq!(authority, "example.com");
    assert_eq!(status, 200);
}

#[test]
fn identity_home_from_path_exposes_partial_name_and_path() {
    let identity_home = IdentityHome::from_path("/tmp/reimu.pilot").unwrap();

    assert_eq!(identity_home.name(), "reimu.pilot");
    assert_eq!(identity_home.path(), Path::new("/tmp/reimu.pilot"));
}

#[test]
fn home_identity_home_expands_partial_name_under_home_path() {
    let home = Home::from_path("/tmp/dhttp-home");
    let identity_home = home.identity_home("reimu.pilot").unwrap();

    assert_eq!(home.path(), Path::new("/tmp/dhttp-home"));
    assert_eq!(identity_home.name(), "reimu.pilot");
    assert_eq!(
        identity_home.path(),
        Path::new("/tmp/dhttp-home/reimu.pilot")
    );
}

#[test]
fn invalid_name_returns_dhttp_error_operation() {
    let home = Home::from_path("/tmp/dhttp-home");
    let error = home.identity_home("!!!").unwrap_err();

    assert_eq!(error.operation(), "home.identity_home");
    assert!(error.message().contains("invalid characters"));
    assert!(!error.report().is_empty());
    assert!(!error.causes().is_empty());
}

#[tokio::test]
async fn identity_exists_reports_invalid_name_operation() {
    let home = Home::from_path("/tmp/dhttp-home");
    let error = home.identity_exists("!!!").await.unwrap_err();

    assert_eq!(error.operation(), "home.identity_exists");
}

#[test]
fn identity_der_getters_are_available() {
    let core = dhttp::identity::Identity::new(
        "reimu.pilot.genmeta.net".parse().unwrap(),
        vec![CertificateDer::from(vec![1, 2, 3])],
        PrivateKeyDer::Pkcs8(vec![4, 5, 6].into()),
    );
    let identity = Identity::from(core);

    assert_eq!(identity.name(), "reimu.pilot.genmeta.net");
    assert_eq!(identity.cert_chain_der(), vec![vec![1, 2, 3]]);
    assert_eq!(identity.public_key_der(), vec![1, 2, 3]);
}

#[test]
fn identity_preserves_core_conversions_and_access() {
    let name = "reimu.pilot".parse::<DhttpName>().unwrap();
    let core = dhttp::identity::Identity::new(
        name.into_name(),
        vec![CertificateDer::from(vec![7, 8, 9])],
        PrivateKeyDer::Pkcs8(vec![10].into()),
    );
    let wrapper = Identity::from(core.clone());

    assert_eq!(wrapper.as_ref().name().as_str(), "reimu.pilot.genmeta.net");
    let roundtrip: dhttp::identity::Identity = wrapper.into();
    assert_eq!(roundtrip.name().as_str(), core.name().as_str());
}

#[tokio::test]
async fn identities_lists_existing_identity_directories_with_ssl_subdir() {
    let base = unique_temp_path("identities-list");
    let _ = tokio::fs::remove_dir_all(&base).await;
    tokio::fs::create_dir_all(base.join("reimu.pilot").join("ssl"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(base.join("ignored.no-ssl"))
        .await
        .unwrap();
    let home = Home::from_path(&base);

    let identities = home.identities().await.unwrap();

    assert_eq!(identities, vec!["reimu.pilot".to_string()]);
}

fn unique_temp_path(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("dhttp-api-{test_name}-{}", std::process::id()))
}

#[test]
fn dhttp_error_can_be_created_from_any_error() {
    let error = DhttpError::from_error(
        "test.operation",
        std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    );

    assert_eq!(error.operation(), "test.operation");
    assert_eq!(format!("{error}"), "test.operation failed");
    assert!(error.report().contains("not found"));
}

#[test]
fn dhttp_error_preserves_nested_report_when_wrapped() {
    let inner = DhttpError::from_error(
        "inner.operation",
        std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    );

    let outer = DhttpError::from_error("outer.operation", inner);

    assert_eq!(outer.operation(), "outer.operation");
    assert!(outer.report().contains("not found"));
    assert!(
        outer
            .causes()
            .iter()
            .any(|cause| cause.contains("not found"))
    );
}
