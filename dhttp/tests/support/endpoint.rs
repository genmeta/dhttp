/// In-memory credentials for tests that do not perform a TLS handshake.
pub fn named(name: &str) -> crate::Endpoint {
    let name = dhttp_home::normalize_name(name).unwrap();
    let generated = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
    let identity = qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        &name,
        vec![generated.cert.der().clone()],
        qtls::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
        b"test-ocsp".to_vec(),
    )
    .unwrap();
    crate::Endpoint::new(Some(identity))
}
