use super::*;
use std::borrow::Cow;

#[test]
fn name_try_from_static_lowercase() {
    let n = Name::try_from_static(b"example.com").unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_static_mixed_case() {
    let n = Name::try_from_static(b"Example.COM").unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_static_wildcard() {
    let n = Name::try_from_static(b"*.example.com").unwrap();
    assert!(n.is_wildcard());
    assert_eq!(n.as_str(), "*.example.com");
}

#[test]
fn name_try_from_static_invalid() {
    let err = Name::try_from_static(b"!!!").unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

#[test]
fn name_try_from_static_bytes_reuses_static_bytes_path() {
    let name = Name::try_from_static(b"Example.COM").unwrap();

    assert_eq!(name.as_str(), "example.com");
}

#[test]
fn name_from_str_trait() {
    let n: Name = "example.com".parse().unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_from_str_trait_rejects_invalid() {
    let result: Result<Name, _> = "INVALID!!!".parse();
    assert!(result.is_err());
}

#[test]
fn name_from_dhttp_shorthand_leaves_plain_name_unchanged() {
    let input = "alice.margatroid";

    let name = Name::from_dhttp_shorthand(input).expect("plain name should parse");

    assert_eq!(name.as_full(), "alice.margatroid");
}

#[test]
fn name_from_dhttp_shorthand_borrows_lowercase_without_marker() {
    let input = "alice.margatroid";

    let name = Name::from_dhttp_shorthand(input).expect("plain name should parse");

    assert_eq!(name.as_full(), "alice.margatroid");
    assert_eq!(name.as_str().as_ptr(), input.as_ptr());
}

#[test]
fn name_from_dhttp_shorthand_reuses_owned_bytes_without_marker() {
    let input = Bytes::from_static(b"alice.margatroid");
    let input_ptr = input.as_ptr();

    let name = Name::from_dhttp_shorthand(input).expect("plain name should parse");
    let bytes = name.into_bytes();

    assert_eq!(bytes.as_ref(), b"alice.margatroid");
    assert_eq!(bytes.as_ptr(), input_ptr);
}

#[test]
fn name_from_dhttp_shorthand_lowercases_plain_name() {
    let name =
        Name::from_dhttp_shorthand("Alice.Margatroid").expect("mixed-case name should parse");

    assert_eq!(name.as_full(), "alice.margatroid");
}

#[test]
fn name_from_dhttp_shorthand_expands_suffix_marker() {
    let name =
        Name::from_dhttp_shorthand("alice.margatroid~").expect("dhttp shorthand should parse");

    assert_eq!(name.as_full(), "alice.margatroid.dhttp.net");
}

#[test]
fn name_from_dhttp_shorthand_expands_every_suffix_marker() {
    let name = Name::from_dhttp_shorthand("alice~bar")
        .expect("any-position dhttp shorthand should parse when expanded name is valid");

    assert_eq!(name.as_full(), "alice.dhttp.netbar");
}

#[test]
fn name_from_dhttp_shorthand_rejects_bare_suffix_marker() {
    let error = Name::from_dhttp_shorthand("~").expect_err("bare shorthand is not a name");

    assert!(matches!(error, InvalidName::EmptyLabel { .. }));
}

#[test]
fn name_from_dhttp_shorthand_accepts_owned_bytes() {
    let name = Name::from_dhttp_shorthand(Bytes::from_static(b"alice~"))
        .expect("owned bytes shorthand should parse");

    assert_eq!(name.as_full(), "alice.dhttp.net");
}

#[test]
fn name_try_from_str_valid() {
    let n: Name = "example.com".parse().unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_str_too_long() {
    let long = "a".repeat(254);
    let err: Result<Name, _> = long.parse();
    assert!(matches!(err.unwrap_err(), InvalidName::TooLong {}));
}

#[test]
fn name_try_from_str_empty() {
    let err: Result<Name, _> = "".parse();
    assert!(matches!(err.unwrap_err(), InvalidName::EmptyLabel {}));
}

#[test]
fn name_try_from_str_invalid_char() {
    let err: Result<Name, _> = "hello!".parse();
    assert!(matches!(err.unwrap_err(), InvalidName::InvalidCharacter {}));
}

#[test]
fn name_try_from_str_label_too_long() {
    let long_label = format!("{}.com", "a".repeat(64));
    let err: Result<Name, _> = long_label.parse();
    assert!(matches!(err.unwrap_err(), InvalidName::LabelTooLong {}));
}

#[test]
fn name_wildcard() {
    let n: Name = "*.example.com".parse().unwrap();
    assert!(n.is_wildcard());

    let m: Name = "foo.example.com".parse().unwrap();
    assert!(n.matches(&m));
    assert!(n.matches(&n));
}

#[test]
fn name_no_wildcard_match() {
    let n: Name = "a.example.com".parse().unwrap();
    let m: Name = "b.example.com".parse().unwrap();
    assert!(!n.matches(&m));
}

#[test]
fn name_exact_match() {
    let n: Name = "foo.example.com".parse().unwrap();
    let m: Name = "foo.example.com".parse().unwrap();
    assert!(n.matches(&m));
}

#[test]
fn name_hash_borrow_consistency() {
    use std::collections::HashSet;
    let n: Name = "example.com".parse().unwrap();
    let mut set = HashSet::new();
    set.insert(n.clone());
    assert!(set.contains("example.com"));
}

#[test]
fn name_clone_owned() {
    let n: Name = "example.com".parse().unwrap();
    let c = n.clone();
    assert_eq!(n, c);
}

#[test]
fn name_to_wildcard_name() {
    let n: Name = "foo.example.com".parse().unwrap();
    let w = n.to_wildcard();
    assert!(w.is_wildcard());
    assert_eq!(w.as_str(), "*.example.com");
}

#[test]
fn name_wildcard_already() {
    let n: Name = "*.example.com".parse().unwrap();
    let w = n.to_wildcard();
    assert_eq!(w.as_str(), "*.example.com");
}

#[test]
fn name_serialize_deserialize() {
    let n: Name = "example.com".parse().unwrap();
    let json = serde_json::to_string(&n).unwrap();
    assert_eq!(json, r#""example.com""#);
    let d: Name<'static> = serde_json::from_str(&json).unwrap();
    assert_eq!(n, d);
}

#[test]
fn name_display() {
    let n: Name = "Example.COM".parse().unwrap();
    assert_eq!(format!("{n}"), "example.com");
}

// --- TryFrom<&str> tests ---

#[test]
fn name_try_from_ref_str_lowercase() {
    let n = Name::try_from("example.com").unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_ref_str_mixed_case() {
    let n = Name::try_from("Example.COM").unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_ref_str_wildcard() {
    let n = Name::try_from("*.example.com").unwrap();
    assert!(n.is_wildcard());
    assert_eq!(n.as_str(), "*.example.com");
}

#[test]
fn name_try_from_ref_str_invalid() {
    let err = Name::try_from("!!!").unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

#[test]
fn name_try_from_ref_str_borrowed_variant() {
    let input = "example.com";
    let n = Name::try_from(input).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

// --- TryFrom<&[u8]> tests ---

#[test]
fn name_try_from_ref_bytes_lowercase() {
    let input: &[u8] = b"example.com";
    let n = Name::try_from(input).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_ref_bytes_mixed_case() {
    let input: &[u8] = b"Example.COM";
    let n = Name::try_from(input).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_ref_bytes_wildcard() {
    let input: &[u8] = b"*.example.com";
    let n = Name::try_from(input).unwrap();
    assert!(n.is_wildcard());
    assert_eq!(n.as_str(), "*.example.com");
}

#[test]
fn name_try_from_ref_bytes_invalid() {
    let input: &[u8] = b"!!!";
    let err = Name::try_from(input).unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

// --- TryFrom<String> tests ---

#[test]
fn name_try_from_string_mixed_case() {
    let s = String::from("Hello.World");
    let n = Name::try_from(s).unwrap();
    assert_eq!(n.as_str(), "hello.world");
}

#[test]
fn name_try_from_string_invalid() {
    let s = String::from("!!!");
    let err = Name::try_from(s).unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

#[test]
fn name_try_from_string_empty() {
    let s = String::new();
    let err = Name::try_from(s).unwrap_err();
    assert!(matches!(err, InvalidName::EmptyLabel {}));
}

// --- TryFrom<Vec<u8>> tests ---

#[test]
fn name_try_from_vec_u8_lowercase() {
    let n = Name::try_from(b"example.com".to_vec()).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_vec_u8_mixed_case() {
    let n = Name::try_from(b"Hello.World".to_vec()).unwrap();
    assert_eq!(n.as_str(), "hello.world");
}

#[test]
fn name_try_from_vec_u8_invalid() {
    let err = Name::try_from(b"!!!".to_vec()).unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

// --- TryFrom<Cow<str>> tests ---

#[test]
fn name_try_from_cow_borrowed_lowercase() {
    let cow: Cow<'_, str> = Cow::Borrowed("example.com");
    let n = Name::try_from(cow).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_cow_borrowed_mixed_case() {
    let cow: Cow<'_, str> = Cow::Borrowed("Example.COM");
    let n = Name::try_from(cow).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_cow_owned_lowercase() {
    let cow: Cow<'_, str> = Cow::Owned("example.com".to_string());
    let n = Name::try_from(cow).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_cow_owned_mixed_case() {
    let cow: Cow<'_, str> = Cow::Owned("Example.COM".to_string());
    let n = Name::try_from(cow).unwrap();
    assert_eq!(n.as_str(), "example.com");
}

#[test]
fn name_try_from_cow_invalid() {
    let cow: Cow<'_, str> = Cow::Borrowed("!!!");
    let err = Name::try_from(cow).unwrap_err();
    assert!(matches!(err, InvalidName::InvalidCharacter {}));
}

#[test]
fn name_try_from_cow_bytes_borrowed_and_owned() {
    let borrowed = Cow::<[u8]>::Borrowed(b"Example.COM");
    let owned: Cow<'_, [u8]> = Cow::Owned(b"Reimu.Pilot".to_vec());

    let borrowed_name = Name::try_from(borrowed).unwrap();
    let owned_name = Name::try_from(owned).unwrap();

    assert_eq!(borrowed_name.as_str(), "example.com");
    assert_eq!(owned_name.as_str(), "reimu.pilot");
}

// --- DhttpName tests ---

#[test]
fn dhttp_name_suffix_is_dhttp_net() {
    assert_eq!(DhttpName::SUFFIX, ".dhttp.net");
}

#[test]
fn dhttp_name_parse_full() {
    let dn = "hello.dhttp.net".parse::<DhttpName>().unwrap();
    assert_eq!(dn.as_full(), "hello.dhttp.net");
    assert_eq!(dn.as_partial(), "hello");
}

#[test]
fn dhttp_name_parse_partial_multi_label() {
    let dn = "reimu.pilot".parse::<DhttpName>().unwrap();
    assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
    assert_eq!(dn.as_partial(), "reimu.pilot");
}

#[test]
fn dhttp_name_parse_partial_single_label_rejected() {
    let name = "hello".parse::<DhttpName>().unwrap();

    assert_eq!(name.as_full(), "hello.dhttp.net");
}

#[test]
fn dhttp_name_serialize() {
    let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let json = serde_json::to_string(&dn).unwrap();
    assert_eq!(json, "\"reimu.pilot\"");
}

#[test]
fn dhttp_name_deserialize_from_partial() {
    let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot\"").unwrap();
    assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_deserialize_from_full() {
    let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot.dhttp.net\"").unwrap();
    assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_deserialize_rejects_invalid() {
    let result: Result<DhttpName<'static>, _> = serde_json::from_str("\"!!!\"");
    assert!(result.is_err());
}

#[test]
fn dhttp_name_hash_consistent_with_name() {
    use std::hash::{DefaultHasher, Hasher};
    let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let n = Name::try_from_static(b"reimu.pilot.dhttp.net").unwrap();
    let hash_dn = {
        let mut h = DefaultHasher::new();
        dn.hash(&mut h);
        h.finish()
    };
    let hash_n = {
        let mut h = DefaultHasher::new();
        n.hash(&mut h);
        h.finish()
    };
    assert_eq!(hash_dn, hash_n);
}

#[test]
fn dhttp_name_eq() {
    let a = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let b = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let c = "other.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn dhttp_name_to_owned_and_clone() {
    let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let owned = dn.to_owned();
    assert_eq!(owned.as_full(), "reimu.pilot.dhttp.net");
    let cloned = owned.clone();
    assert_eq!(cloned.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_into_owned() {
    let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
    let owned = dn.into_owned();
    assert_eq!(owned.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_to_wildcard_replaces_first_label() {
    let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();

    let wildcard = dn.to_wildcard();

    assert_eq!(wildcard.as_full(), "*.pilot.dhttp.net");
}

#[test]
fn dhttp_name_from_str_trait() {
    let dn: DhttpName = "reimu.pilot.dhttp.net".parse().unwrap();
    assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_from_str_trait_rejects_invalid() {
    let result: Result<DhttpName, _> = "!!!".parse();
    assert!(result.is_err());
}

#[test]
fn dhttp_name_legacy_borrow_method() {
    let dn = "reimu.pilot".parse::<DhttpName>().unwrap();
    let borrowed = dn.borrow();
    assert_eq!(borrowed.as_full(), dn.as_full());
}

#[test]
fn dhttp_name_legacy_validate() {
    DhttpName::validate(b"reimu.pilot.dhttp.net").unwrap();
    assert!(DhttpName::validate(b"reimu.pilot").is_err());
}

#[test]
fn dhttp_name_try_from_str_expands_partial_name() {
    let name = DhttpName::try_from("reimu.pilot").unwrap();
    assert_eq!(name.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_try_from_string_expands_tilde_name() {
    let name = DhttpName::try_from(String::from("reimu.pilot~")).unwrap();
    assert_eq!(name.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_try_from_bytes_and_cow_bytes_append_suffix() {
    let from_bytes = DhttpName::try_from(Bytes::from_static(b"Reimu.Pilot")).unwrap();
    let from_cow: DhttpName<'_> = DhttpName::try_from(Cow::<[u8]>::Borrowed(b"Device")).unwrap();

    assert_eq!(from_bytes.as_full(), "reimu.pilot.dhttp.net");
    assert_eq!(from_cow.as_full(), "device.dhttp.net");
}

#[test]
fn dhttp_name_try_from_static_bytes_appends_suffix() {
    let name = DhttpName::try_from_static(b"Device").unwrap();

    assert_eq!(name.as_full(), "device.dhttp.net");
}

#[test]
fn dhttp_name_try_from_name_accepts_full_name_without_reparsing_string() {
    let name = Name::try_from("reimu.pilot.dhttp.net").unwrap();

    let dhttp_name = DhttpName::try_from(name).unwrap();

    assert_eq!(dhttp_name.as_full(), "reimu.pilot.dhttp.net");
}

#[test]
fn dhttp_name_try_from_name_rejects_missing_suffix() {
    let name = Name::try_from("example.com").unwrap();

    let error = DhttpName::try_from(name).unwrap_err();

    assert!(matches!(
        error,
        InvalidDhttpName::InvalidName {
            source: InvalidName::MissingSuffix { .. }
        }
    ));
}

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
