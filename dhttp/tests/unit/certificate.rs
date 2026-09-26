use super::*;
#[test]
fn subject_is_the_canonical_textual_owner_hash() {
    let certificate = qtls::CertificateDer::from(
        include_bytes!("../../../identity/tests/fixtures/valid.der").as_slice(),
    );
    assert_eq!(
        subject_id(&[certificate]).unwrap(),
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert!(subject_id(&[]).is_err());
    assert!(subject_id(&[qtls::CertificateDer::from(b"invalid".as_slice())]).is_err());
}
#[test]
fn canonical_signatures_verify_and_detect_modified_messages() {
    let generated =
        rcgen::generate_simple_self_signed(vec!["signer.dhttp.net".to_owned()]).unwrap();
    let authority = qtls::LocalAuthority::new(
        &qtls::default_provider(),
        Arc::from("signer.dhttp.net"),
        vec![generated.cert.der().clone()],
        qtls::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
        vec![1],
    )
    .unwrap();
    let signature = sign(&authority, b"message").unwrap();
    assert!(verify_signature(authority.public_key().as_ref(), b"message", &signature).unwrap());
    assert!(!verify_signature(authority.public_key().as_ref(), b"different", &signature).unwrap());
    assert!(verify_signature(b"invalid", b"message", &signature).is_err());
}
