use chrono::{FixedOffset, TimeZone};
use dhttp_identity::certificate::{CertificateChainKey, CertificateChainKind, CertificateSequence};
use dhttp_log::cert::{
    CertificateAction, CertificateIssuer, CertificateLogRecord, CertificateUsage,
    DefaultCertificateFormatter, Sha256Fingerprint,
};
use sha2::{Digest, Sha256};

const LEAF_DER: &[u8] = include_bytes!("fixtures/leaf.der");

fn timestamp(
    offset_seconds: i32,
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> chrono::DateTime<FixedOffset> {
    FixedOffset::east_opt(offset_seconds)
        .unwrap()
        .with_ymd_and_hms(year, month, day, hour, minute, second)
        .unwrap()
}

fn chain() -> CertificateChainKey {
    CertificateChainKey::new(
        CertificateSequence::try_from(0_u32).unwrap(),
        CertificateChainKind::Primary,
    )
}

fn certificate_fixture() -> CertificateLogRecord {
    CertificateLogRecord {
        recorded_at: timestamp(0, 2026, 7, 13, 8, 20, 31),
        action: CertificateAction::Apply,
        issuer: Some(CertificateIssuer::from("Genmeta Tech Limited")),
        usage: CertificateUsage::ClientOnly,
        chain: chain(),
        expires_at: timestamp(0, 2027, 7, 13, 8, 20, 30),
        fingerprint: Sha256Fingerprint::from([0_u8; 32]),
    }
}

fn replace_first(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture contains mutation target");
    bytes[offset..offset + needle.len()].copy_from_slice(replacement);
}

fn record_from_leaf(leaf_der: &[u8]) -> CertificateLogRecord {
    CertificateLogRecord::from_leaf_der(
        timestamp(0, 2026, 7, 13, 8, 20, 31),
        CertificateAction::Apply,
        chain(),
        leaf_der,
    )
    .unwrap()
}

#[test]
fn certificate_record_uses_standard_timestamps_and_builtin_formatter() {
    let recorded_at = chrono::DateTime::parse_from_rfc3339("2026-07-13T08:20:31+00:00").unwrap();
    let record = CertificateLogRecord::from_leaf_der(
        recorded_at,
        CertificateAction::Apply,
        chain(),
        LEAF_DER,
    )
    .unwrap();
    let formatted = DefaultCertificateFormatter::format(&record).unwrap();
    assert!(
        formatted
            .as_bytes()
            .starts_with(b"[13/Jul/2026:08:20:31 +0000] APPLY ")
    );
    assert!(formatted.as_bytes().ends_with(b"\n"));
}

#[test]
fn default_certificate_line_formats_sha256_fingerprint_and_existing_chain_key() {
    let line = DefaultCertificateFormatter::format(&certificate_fixture()).unwrap();

    assert_eq!(
        line.as_bytes(),
        b"[13/Jul/2026:08:20:31 +0000] APPLY \"Genmeta Tech Limited\" \"client only\" primary:0 [13/Jul/2027:08:20:30 +0000] \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n"
    );
}

#[test]
fn certificate_from_leaf_der_hashes_exact_leaf_bytes() {
    let record = record_from_leaf(LEAF_DER);
    let expected: [u8; 32] = Sha256::digest(LEAF_DER).into();

    assert_eq!(record.fingerprint, Sha256Fingerprint::from(expected));
    assert_eq!(record.fingerprint.as_bytes(), &expected);
    assert_eq!(record.expires_at.timestamp(), 1_815_502_014);
}

#[test]
fn certificate_from_leaf_der_rejects_trailing_data() {
    let mut leaf_with_junk = LEAF_DER.to_vec();
    leaf_with_junk.extend_from_slice(b"junk");

    let error = CertificateLogRecord::from_leaf_der(
        timestamp(0, 2026, 7, 13, 8, 20, 31),
        CertificateAction::Apply,
        chain(),
        &leaf_with_junk,
    )
    .expect_err("trailing bytes are not part of the leaf DER value");
    assert!(matches!(
        error,
        dhttp_log::cert::CertificateLogRecordFromLeafDerError::TrailingData { len: 4 }
    ));
}

#[test]
fn certificate_from_leaf_der_rejects_concatenated_certificates() {
    let mut concatenated = LEAF_DER.to_vec();
    concatenated.extend_from_slice(LEAF_DER);

    let error = CertificateLogRecord::from_leaf_der(
        timestamp(0, 2026, 7, 13, 8, 20, 31),
        CertificateAction::Apply,
        chain(),
        &concatenated,
    )
    .expect_err("a second certificate is trailing data, not part of the leaf");
    assert!(matches!(
        error,
        dhttp_log::cert::CertificateLogRecordFromLeafDerError::TrailingData { len }
            if len == LEAF_DER.len()
    ));
}

#[test]
fn certificate_issuer_prefers_first_valid_utf8_organization_then_common_name_then_missing() {
    let organization = record_from_leaf(LEAF_DER);
    assert_eq!(
        organization.issuer.as_ref().map(CertificateIssuer::as_str),
        Some("Genmeta Tech Limited")
    );

    let mut common_name_der = LEAF_DER.to_vec();
    replace_first(
        &mut common_name_der,
        &[0x06, 0x03, 0x55, 0x04, 0x0a],
        &[0x06, 0x03, 0x55, 0x04, 0x7f],
    );
    let common_name = record_from_leaf(&common_name_der);
    assert_eq!(
        common_name.issuer.as_ref().map(CertificateIssuer::as_str),
        Some("leaf.example.dhttp.net")
    );

    replace_first(
        &mut common_name_der,
        &[0x06, 0x03, 0x55, 0x04, 0x03],
        &[0x06, 0x03, 0x55, 0x04, 0x7e],
    );
    let missing = record_from_leaf(&common_name_der);
    assert_eq!(missing.issuer.as_ref().map(CertificateIssuer::as_str), None);
}

#[test]
fn certificate_issuer_skips_invalid_utf8_organization() {
    let mut leaf_der = LEAF_DER.to_vec();
    replace_first(
        &mut leaf_der,
        b"Genmeta Tech Limited",
        b"Genmeta Tech Limite\xff",
    );

    let record = record_from_leaf(&leaf_der);

    assert_eq!(
        record.issuer.as_ref().map(CertificateIssuer::as_str),
        Some("leaf.example.dhttp.net")
    );
}

#[test]
fn certificate_usage_maps_client_server_both_absent_and_other_eku() {
    const CLIENT_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    const SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    const OTHER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x7f];

    assert_eq!(
        record_from_leaf(LEAF_DER).usage,
        CertificateUsage::ClientAndServer
    );

    let mut client_only = LEAF_DER.to_vec();
    replace_first(&mut client_only, SERVER_AUTH, OTHER_AUTH);
    assert_eq!(
        record_from_leaf(&client_only).usage,
        CertificateUsage::ClientOnly
    );

    let mut server_only = LEAF_DER.to_vec();
    replace_first(&mut server_only, CLIENT_AUTH, OTHER_AUTH);
    assert_eq!(
        record_from_leaf(&server_only).usage,
        CertificateUsage::ServerOnly
    );

    replace_first(&mut server_only, SERVER_AUTH, OTHER_AUTH);
    assert_eq!(
        record_from_leaf(&server_only).usage,
        CertificateUsage::Other
    );

    let mut absent = LEAF_DER.to_vec();
    replace_first(
        &mut absent,
        &[0x06, 0x03, 0x55, 0x1d, 0x25],
        &[0x06, 0x03, 0x55, 0x1d, 0x7f],
    );
    assert_eq!(
        record_from_leaf(&absent).usage,
        CertificateUsage::Unrestricted
    );
}

#[test]
fn certificate_action_and_usage_have_canonical_formatting() {
    let cases = [
        (
            CertificateAction::Apply,
            CertificateUsage::ClientOnly,
            b" APPLY \"Genmeta Tech Limited\" \"client only\" ".as_slice(),
        ),
        (
            CertificateAction::Renew,
            CertificateUsage::ServerOnly,
            b" RENEW \"Genmeta Tech Limited\" \"server only\" ".as_slice(),
        ),
        (
            CertificateAction::Replace,
            CertificateUsage::ClientAndServer,
            b" REPLACE \"Genmeta Tech Limited\" \"client and server\" ".as_slice(),
        ),
        (
            CertificateAction::Apply,
            CertificateUsage::Unrestricted,
            b" APPLY \"Genmeta Tech Limited\" \"unrestricted\" ".as_slice(),
        ),
        (
            CertificateAction::Apply,
            CertificateUsage::Other,
            b" APPLY \"Genmeta Tech Limited\" \"other\" ".as_slice(),
        ),
    ];

    for (action, usage, expected) in cases {
        let mut record = certificate_fixture();
        record.action = action;
        record.usage = usage;
        let line = DefaultCertificateFormatter::format(&record).unwrap();
        assert!(
            line.as_bytes()
                .windows(expected.len())
                .any(|window| window == expected)
        );
    }
}

#[test]
fn certificate_issuer_field_escapes_quote_control_non_ascii_and_backslash() {
    let mut record = certificate_fixture();
    record.issuer = Some(CertificateIssuer::from("Org\"\u{1}é\\"));

    let line = DefaultCertificateFormatter::format(&record).unwrap();

    assert!(
        line.as_bytes()
            .windows(b"\"Org\\\"\\x01\\xc3\\xa9\\\\\"".len())
            .any(|window| window == b"\"Org\\\"\\x01\\xc3\\xa9\\\\\"")
    );
}

#[test]
fn certificate_and_access_formats_share_clf_timestamp_output() {
    let value = timestamp(8 * 60 * 60, 2026, 7, 13, 16, 20, 31);
    let mut certificate = certificate_fixture();
    certificate.recorded_at = value;
    let certificate_line = DefaultCertificateFormatter::format(&certificate).unwrap();
    let access_line =
        dhttp_log::access::DefaultAccessFormatter::format(&access_record_at(value)).unwrap();
    let expected = b"[13/Jul/2026:16:20:31 +0800]";
    assert!(
        certificate_line
            .as_bytes()
            .windows(expected.len())
            .any(|window| window == expected)
    );
    assert!(
        access_line
            .as_bytes()
            .windows(expected.len())
            .any(|window| window == expected)
    );
}

fn access_record_at(
    completed_at: chrono::DateTime<FixedOffset>,
) -> dhttp_log::access::AccessLogRecord {
    use dhttp_log::access::{
        AccessLogRecord, AccessRequestTarget, BodyBytesEmitted, ClientAddress, OptionalReferer,
        OptionalUserAgent,
    };
    use http::{HeaderMap, Method, StatusCode, Version};

    let headers = HeaderMap::new();
    AccessLogRecord {
        completed_at,
        client: ClientAddress::Unknown,
        method: Method::GET,
        target: "/".parse::<AccessRequestTarget>().unwrap(),
        version: Version::HTTP_3,
        status: StatusCode::OK,
        body_bytes: BodyBytesEmitted::ZERO,
        referer: OptionalReferer::from(&headers),
        user_agent: OptionalUserAgent::from(&headers),
    }
}
