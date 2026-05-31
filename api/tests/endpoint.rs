use dhttp_api::{
    endpoint::{Endpoint, EndpointOptions},
    identity::Identity,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn endpoint_options_are_mutable_class_like_values() {
    let mut options = EndpointOptions::new();

    assert!(options.identity().is_none());
    assert!(options.dns_schemes().is_empty());
    assert!(options.bind_patterns().is_empty());

    options.add_dns_scheme("mdns").unwrap();
    options.add_dns_scheme("system").unwrap();
    options.add_bind_pattern("*").unwrap();
    options.set_identity(test_identity());

    assert!(options.identity().is_some());
    assert_eq!(options.dns_schemes(), vec!["mdns", "system"]);
    assert_eq!(options.bind_patterns(), vec!["iface://*"]);
}

#[test]
fn endpoint_options_report_invalid_dns_scheme_operation() {
    let mut options = EndpointOptions::new();

    let error = options.add_dns_scheme("bogus").unwrap_err();

    assert_eq!(error.operation(), "endpoint_options.add_dns_scheme");
}

#[tokio::test]
async fn endpoint_create_uses_options_and_exposes_identity_and_binds() {
    let mut options = EndpointOptions::new();
    options.add_bind_pattern("*").unwrap();
    options.set_identity(test_identity());

    let endpoint = Endpoint::create(Some(options)).await.unwrap();

    assert_eq!(
        endpoint.identity().unwrap().name(),
        "reimu.pilot.genmeta.net"
    );
    assert_eq!(endpoint.bind_patterns(), vec!["iface://*"]);
}

#[tokio::test]
async fn endpoint_serve_returns_abortable_handle() {
    let endpoint = Endpoint::create(None).await.unwrap();

    let handle = endpoint.listen_streams(|_incoming| Box::pin(async { Ok(()) }));

    handle.abort();
}

#[allow(dead_code)]
async fn endpoint_low_level_client_stream_api_is_exposed(endpoint: &Endpoint) {
    let connection = endpoint.connect("example.com").await.unwrap();
    let (_read_stream, _write_stream) = connection.open_request_stream().await.unwrap();
}

fn test_identity() -> Identity {
    dhttp::identity::Identity::new(
        "reimu.pilot.genmeta.net".parse().unwrap(),
        vec![CertificateDer::from(vec![1, 2, 3])],
        PrivateKeyDer::Pkcs8(vec![4, 5, 6].into()),
    )
    .into()
}

#[tokio::test]
async fn serve_handle_closed_does_not_require_mut_binding() {
    let endpoint = Endpoint::create(None).await.unwrap();
    let handle = endpoint.listen_streams(|_incoming| Box::pin(async { Ok(()) }));

    handle.abort();
    handle.closed().await.unwrap();
}
