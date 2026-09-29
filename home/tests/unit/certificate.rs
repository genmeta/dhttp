use super::*;

const OWNER_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn certificate_sequence_accepts_database_compatible_range() {
    assert_eq!(CertificateSequence::from(7u8).get(), 7);
    assert_eq!(CertificateSequence::from(u16::MAX).get(), u16::MAX as u32);
    assert_eq!(CertificateSequence::try_from(0u32).unwrap().get(), 0);
    assert_eq!(
        CertificateSequence::try_from(i32::MAX as u32)
            .unwrap()
            .get(),
        i32::MAX as u32
    );
    assert_eq!(
        CertificateSequence::try_from(i32::MAX as u64)
            .unwrap()
            .get(),
        i32::MAX as u32
    );
}

#[test]
fn certificate_sequence_rejects_values_outside_database_range() {
    assert!(matches!(
        CertificateSequence::try_from(-1),
        Err(InvalidCertificateSequence::Negative)
    ));
    assert!(matches!(
        CertificateSequence::try_from(i32::MAX as u32 + 1),
        Err(InvalidCertificateSequence::OutOfRange { .. })
    ));
    assert!(matches!(
        CertificateSequence::try_from(i32::MAX as u64 + 1),
        Err(InvalidCertificateSequence::OutOfRange { .. })
    ));
}

#[test]
fn certificate_chain_key_displays_user_facing_label() {
    let primary = CertificateChainKey::new(
        CertificateSequence::try_from(0u32).unwrap(),
        CertificateUsage::ClientAndServer,
    );
    let secondary = CertificateChainKey::new(
        CertificateSequence::try_from(2u32).unwrap(),
        CertificateUsage::ClientOnly,
    );

    assert_eq!(primary.to_string(), "client and server:0");
    assert_eq!(secondary.to_string(), "client:2");
}

#[test]
fn certificate_usage_preserves_certserver_kind_flags() {
    assert_eq!(CertificateUsage::ClientAndServer.kind_flag(), "0");
    assert_eq!(CertificateUsage::ClientOnly.kind_flag(), "1");
}

#[test]
fn rejects_out_of_range_subject_key_identifier_sequence() {
    let error = format!("{}:0:{OWNER_HASH}", i32::MAX as u64 + 1)
        .parse::<DhttpSubjectKeyIdentifier>()
        .unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::SequenceRange { .. }
    ));
}

#[test]
fn parses_canonical_dhttp_subject_key_identifier() {
    let ski = DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(
        format!("7:0:{OWNER_HASH}").as_bytes(),
    )
    .unwrap();

    assert_eq!(ski.chain().sequence().get(), 7);
    assert_eq!(ski.chain().usage(), CertificateUsage::ClientAndServer);
    assert_eq!(ski.owner_hash().as_str(), OWNER_HASH);
    assert_eq!(ski.to_string(), format!("7:0:{OWNER_HASH}"));
}

#[test]
fn rejects_non_utf8_subject_key_identifier() {
    let error =
        DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(&[0xff]).unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::Utf8 { .. }
    ));
}

#[test]
fn rejects_wrong_field_count() {
    let error = "0:1".parse::<DhttpSubjectKeyIdentifier>().unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::FieldCount
    ));
}

#[test]
fn rejects_invalid_sequence() {
    let error = format!("-1:0:{OWNER_HASH}")
        .parse::<DhttpSubjectKeyIdentifier>()
        .unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::Sequence { .. }
    ));
}

#[test]
fn rejects_invalid_kind_flag() {
    let error = format!("0:2:{OWNER_HASH}")
        .parse::<DhttpSubjectKeyIdentifier>()
        .unwrap_err();

    assert!(matches!(error, InvalidDhttpSubjectKeyIdentifier::KindFlag));
}

#[test]
fn rejects_uppercase_owner_hash() {
    let error = format!("0:0:{}", OWNER_HASH.to_ascii_uppercase())
        .parse::<DhttpSubjectKeyIdentifier>()
        .unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::OwnerHash { .. }
    ));
}

#[test]
fn rejects_short_owner_hash() {
    let error = "0:0:abc".parse::<DhttpSubjectKeyIdentifier>().unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpSubjectKeyIdentifier::OwnerHash { .. }
    ));
}
