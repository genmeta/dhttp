#[test]
fn expand_uri_replaces_bare_tilde_with_self_name() {
    let name = "reimu.pilot".parse::<DhttpName>().unwrap();
    let uri = "https://~/api?q=1".parse().unwrap();

    let expanded = name.expand_uri(uri).unwrap();

    assert_eq!(
        expanded.to_string(),
        "https://reimu.pilot.dhttp.net/api?q=1"
    );
}

#[test]
fn expand_uri_expands_tilde_suffix_and_preserves_userinfo_port() {
    let name = "self.host".parse::<DhttpName>().unwrap();
    let uri = "https://alice@reimu.pilot~:443/api".parse().unwrap();

    let expanded = name.expand_uri(uri).unwrap();

    assert_eq!(
        expanded.to_string(),
        "https://alice@reimu.pilot.dhttp.net:443/api"
    );
}

#[test]
fn expand_authority_expands_tilde_suffix_and_preserves_userinfo_port() {
    let name = "self.host".parse::<DhttpName>().unwrap();
    let authority = "alice@reimu.pilot~:443".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(Some(&name), authority).unwrap();

    assert_eq!(expanded.as_str(), "alice@reimu.pilot.dhttp.net:443");
}

#[test]
fn expand_authority_expands_any_position_tilde_suffix() {
    let authority = "alice@a~:443".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

    assert_eq!(expanded.as_str(), "alice@a.dhttp.net:443");
}

#[test]
fn expand_authority_expands_middle_tilde_suffix() {
    let authority = "a~b".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

    assert_eq!(expanded.as_str(), "a.dhttp.netb");
}

#[test]
fn expand_authority_keeps_bare_tilde_as_self_with_base() {
    let base = "reimu.pilot".parse::<DhttpName>().unwrap();
    let authority = "~".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(Some(&base), authority).unwrap();

    assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
}

#[test]
fn expand_authority_rejects_invalid_shorthand_host() {
    let authority = "~bar".parse().unwrap();

    let error = DhttpName::expand_authority_with_base(None, authority).unwrap_err();

    assert!(matches!(error, ExpandAuthorityError::InvalidName { .. }));
}

#[test]
fn expand_authority_canonicalizes_mixed_case_host_only_dhttp_name() {
    let authority = "Reimu.Pilot.Dhttp.Net".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

    assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
}

#[test]
fn expand_authority_canonicalizes_mixed_case_decorated_dhttp_name() {
    let authority = "alice@Reimu.Pilot.Dhttp.Net:443".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

    assert_eq!(expanded.as_str(), "alice@reimu.pilot.dhttp.net:443");
}

#[test]
fn expand_authority_host_only_partial_uses_canonical_name() {
    let authority = "Reimu.Pilot~".parse().unwrap();

    let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

    assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
}

#[test]
fn expand_authority_with_base_requires_base_name_for_bare_tilde() {
    let authority = "~".parse().unwrap();

    let error = DhttpName::expand_authority_with_base(None, authority).unwrap_err();

    assert!(matches!(error, ExpandAuthorityError::MissingBaseName));
}

#[test]
fn expand_uri_leaves_plain_host_unchanged() {
    let name = "self.host".parse::<DhttpName>().unwrap();
    let uri: http::Uri = "https://example.com/api".parse().unwrap();

    let expanded = name.expand_uri(uri.clone()).unwrap();

    assert_eq!(expanded, uri);
}

#[test]
fn expand_uri_rejects_invalid_expanded_name() {
    let name = "self.host".parse::<DhttpName>().unwrap();
    let uri = "https://123~/api".parse().unwrap();

    let error = name.expand_uri(uri).unwrap_err();

    assert!(matches!(
        error,
        ExpandUriError::Authority {
            source: ExpandAuthorityError::InvalidName { .. }
        }
    ));
}

#[test]
fn expand_uri_with_base_expands_partial_without_base_name() {
    let uri = "https://reimu.pilot~/api".parse().unwrap();

    let expanded = DhttpName::expand_uri_with_base(None, uri).unwrap();

    assert_eq!(expanded.to_string(), "https://reimu.pilot.dhttp.net/api");
}

#[test]
fn expand_uri_with_base_requires_base_name_for_bare_tilde() {
    let uri = "https://~/api".parse().unwrap();

    let error = DhttpName::expand_uri_with_base(None, uri).unwrap_err();

    assert!(matches!(
        error,
        ExpandUriError::Authority {
            source: ExpandAuthorityError::MissingBaseName
        }
    ));
}
