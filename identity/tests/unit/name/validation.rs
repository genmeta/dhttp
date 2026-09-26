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
