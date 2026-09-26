use super::*;

#[test]
fn rfc1123_host_accepts_digit_start_and_rejects_underscore() {
    assert!(ClientNameLanguage::accepts(b"3com.example"));
    assert!(ClientNameLanguage::accepts(b"alice.dhttp.net"));
    assert!(!ClientNameLanguage::accepts(b"_service.example"));
    assert!(!ClientNameLanguage::accepts(b"-bad.example"));
    assert!(!ClientNameLanguage::accepts(b"bad-.example"));
}

#[test]
fn rfc9110_token_domains_accept_tchars() {
    assert!(HttpMethodLanguage::accepts(b"GET"));
    assert!(HttpMethodLanguage::accepts(b"M-SEARCH"));
    assert!(HeaderNameLanguage::accepts(b"content-type"));
    assert!(!HeaderNameLanguage::accepts(b"bad header"));
}

#[test]
fn rfc3986_path_and_query_domains_use_raw_uri_characters() {
    assert!(LocationPathLanguage::accepts(b"/api/a%20b"));
    assert!(!LocationPathLanguage::accepts(b"/api/a%zzb"));
    assert!(!LocationPathLanguage::accepts(b"/api/a%2"));
    assert!(!LocationPathLanguage::accepts(b"api/no-leading-slash"));
    assert!(QueryKeyLanguage::accepts(b"q"));
    assert!(QueryKeyLanguage::accepts(b"q%20name"));
    assert!(!QueryKeyLanguage::accepts(b"q%zzname"));
    assert!(!QueryKeyLanguage::accepts(b"q=name"));
    assert!(!QueryKeyLanguage::accepts(b"q&name"));
    assert!(QueryValueLanguage::accepts(b"a/b?c"));
    assert!(QueryValueLanguage::accepts(b"a=b"));
    assert!(!QueryValueLanguage::accepts(b"a&b"));
    assert!(!QueryValueLanguage::accepts(b"a%"));
}

#[test]
fn reachability_rejects_smart_quote_name_pattern() {
    let pattern: NormalPattern = "“*?”".parse().unwrap();

    let error = validate_reachable::<_, ClientNameLanguage>(&pattern).unwrap_err();

    assert!(matches!(error, ReachabilityError::EmptyIntersection { .. }));
}
