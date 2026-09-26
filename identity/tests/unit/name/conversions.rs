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
