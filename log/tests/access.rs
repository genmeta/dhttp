use std::{error::Error as _, net::IpAddr};

use chrono::{DateTime, FixedOffset};
use dhttp_log::access::{
    AccessLogRecord, AccessRequestTarget, BodyBytesEmitted, ClientAddress, DefaultAccessFormatter,
    InvalidAccessRequestTarget, OptionalReferer, OptionalUserAgent,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version, header};

fn completed_at() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("2026-07-13T16:20:31+08:00").unwrap()
}

fn access_fixture() -> AccessLogRecord {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::REFERER,
        HeaderValue::from_static("https://example.test/"),
    );
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("ExampleAgent/1.0"),
    );

    AccessLogRecord {
        completed_at: completed_at(),
        client: ClientAddress::from("192.0.2.10".parse::<IpAddr>().unwrap()),
        method: Method::GET,
        target: "/assets/a.css".parse().unwrap(),
        version: Version::HTTP_3,
        status: StatusCode::OK,
        body_bytes: BodyBytesEmitted::from(1432_u64),
        referer: OptionalReferer::from(&headers),
        user_agent: OptionalUserAgent::from(&headers),
    }
}

#[test]
fn access_target_keeps_only_uri_path() {
    let uri: Uri = "https://example.test/a/b?token=secret".parse().unwrap();

    assert_eq!(AccessRequestTarget::from(&uri).path(), Some("/a/b"));
}

#[test]
fn default_access_format_is_combined_without_reserved_columns() {
    let line = DefaultAccessFormatter::format(&access_fixture()).unwrap();

    assert_eq!(
        line.as_bytes(),
        b"192.0.2.10 - - [13/Jul/2026:16:20:31 +0800] \"GET /assets/a.css HTTP/3\" 200 1432 \"https://example.test/\" \"ExampleAgent/1.0\"\n"
    );
    assert!(!line.as_bytes().windows(5).any(|bytes| bytes == b"token"));
}

#[test]
fn request_header_values_are_built_from_the_named_allowlist_only() {
    let mut headers = HeaderMap::new();
    headers.insert(header::REFERER, HeaderValue::from_static("https://safe/"));
    headers.insert(header::USER_AGENT, HeaderValue::from_static("SafeAgent"));
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer access-secret"),
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("session=cookie-secret"),
    );
    headers.insert("x-request-body", HeaderValue::from_static("body-secret"));

    let referer = OptionalReferer::from(&headers);
    let user_agent = OptionalUserAgent::from(&headers);

    assert_eq!(referer.value(), Some(b"https://safe/".as_slice()));
    assert_eq!(user_agent.value(), Some(b"SafeAgent".as_slice()));

    let mut record = access_fixture();
    record.referer = referer;
    record.user_agent = user_agent;
    let line = DefaultAccessFormatter::format(&record).unwrap();
    for secret in [
        b"access-secret".as_slice(),
        b"cookie-secret",
        b"body-secret",
    ] {
        assert!(
            !line
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
}

#[test]
fn request_header_allowlist_represents_missing_values() {
    let headers = HeaderMap::new();

    assert_eq!(OptionalReferer::from(&headers).value(), None);
    assert_eq!(OptionalUserAgent::from(&headers).value(), None);

    let mut record = access_fixture();
    record.referer = OptionalReferer::from(&headers);
    record.user_agent = OptionalUserAgent::from(&headers);
    let line = DefaultAccessFormatter::format(&record).unwrap();
    assert!(line.as_bytes().ends_with(b" \"-\" \"-\"\n"));
}

#[test]
fn access_header_fields_escape_quotes_backslashes_and_non_ascii_octets() {
    for &control in b"\0\x1f\x7f" {
        assert!(
            HeaderValue::from_bytes(&[control]).is_err(),
            "HTTP HeaderValue unexpectedly accepted control byte {control:#04x}"
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::REFERER,
        HeaderValue::from_bytes(b"https://example.test/\"\\\x80").unwrap(),
    );
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_bytes(b"Agent/1.0\t\"\\\xff").unwrap(),
    );

    let mut record = access_fixture();
    record.referer = OptionalReferer::from(&headers);
    record.user_agent = OptionalUserAgent::from(&headers);
    let line = DefaultAccessFormatter::format(&record).unwrap();

    assert!(
        line.as_bytes().ends_with(
            b" \"https://example.test/\\\"\\\\\\x80\" \"Agent/1.0\\x09\\\"\\\\\\xff\"\n"
        )
    );
}

#[test]
fn access_target_preserves_asterisk_form() {
    let uri = Uri::from_static("*");

    assert_eq!(AccessRequestTarget::from(&uri).path(), Some("*"));
    assert_eq!(
        "*".parse::<AccessRequestTarget>().unwrap().path(),
        Some("*")
    );
}

#[test]
fn access_target_omits_authority_form_without_leaking_authority() {
    let uri = Uri::builder()
        .authority("private.example:443")
        .build()
        .unwrap();
    let target = AccessRequestTarget::from(&uri);
    assert_eq!(target.path(), None);

    let mut record = access_fixture();
    record.method = Method::CONNECT;
    record.target = target;
    let line = DefaultAccessFormatter::format(&record).unwrap();

    assert!(
        line.as_bytes()
            .windows(b"CONNECT - HTTP/3".len())
            .any(|window| window == b"CONNECT - HTTP/3")
    );
    assert!(
        !line
            .as_bytes()
            .windows(b"private.example".len())
            .any(|window| window == b"private.example")
    );
}

#[test]
fn access_target_parser_accepts_only_asterisk_or_nonempty_absolute_path() {
    assert_eq!(
        "/".parse::<AccessRequestTarget>().unwrap().path(),
        Some("/")
    );
    assert_eq!(
        "/a:b/c".parse::<AccessRequestTarget>().unwrap().path(),
        Some("/a:b/c")
    );

    for rejected in [
        "",
        "relative",
        "https://example.test/path",
        "//example.test/path",
        "example.test:443",
        "/path?token=secret",
        "/path#fragment",
        "/path\rhidden",
        "/path\nhidden",
    ] {
        assert!(
            rejected.parse::<AccessRequestTarget>().is_err(),
            "accepted invalid target {rejected:?}"
        );
    }
}

#[test]
fn access_target_parser_enforces_http_origin_path_bytes() {
    for accepted in ["/absolute/path", "/escaped%20space", "/a:b/c", "*"] {
        assert_eq!(
            accepted.parse::<AccessRequestTarget>().unwrap().path(),
            Some(accepted)
        );
    }

    for rejected in [
        "/with space",
        "/nul\0byte",
        "/tab\tbyte",
        "/delete\u{7f}byte",
        "/raw-é",
        "/path?token=secret",
        "/path#fragment",
        "https://example.test/path",
        "//example.test/path",
    ] {
        assert!(
            rejected.parse::<AccessRequestTarget>().is_err(),
            "accepted invalid HTTP origin path {rejected:?}"
        );
    }

    let invalid_uri = "/with space"
        .parse::<AccessRequestTarget>()
        .expect_err("an unescaped space is not an HTTP path character");
    assert!(invalid_uri.source().is_some());
    assert!(matches!(
        invalid_uri,
        InvalidAccessRequestTarget::InvalidUri { .. }
    ));
}

#[test]
fn default_access_formatter_uses_canonical_http_versions() {
    let cases = [
        (Version::HTTP_09, b"HTTP/0.9".as_slice()),
        (Version::HTTP_10, b"HTTP/1.0".as_slice()),
        (Version::HTTP_11, b"HTTP/1.1".as_slice()),
        (Version::HTTP_2, b"HTTP/2".as_slice()),
        (Version::HTTP_3, b"HTTP/3".as_slice()),
    ];

    for (version, expected) in cases {
        let mut record = access_fixture();
        record.version = version;
        let line = DefaultAccessFormatter::format(&record).unwrap();
        assert!(
            line.as_bytes()
                .windows(expected.len())
                .any(|window| window == expected)
        );
    }
}

#[test]
fn body_bytes_emitted_supports_zero_and_checked_accumulation() {
    assert_eq!(BodyBytesEmitted::ZERO.get(), 0);
    assert_eq!(
        BodyBytesEmitted::ZERO
            .checked_add(4)
            .unwrap()
            .checked_add(5)
            .unwrap()
            .get(),
        9
    );
    assert!(BodyBytesEmitted::from(u64::MAX).checked_add(1).is_none());
}
