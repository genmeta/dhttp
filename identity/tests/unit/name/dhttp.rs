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
