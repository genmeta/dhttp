use super::*;

#[test]
fn client_name_pattern_matches_full_name_without_suffix_trimming() {
    let pattern =
        Pattern::<ClientNamePatternKind>::new("alice").expect("valid client name pattern");

    assert!(pattern.is_match("alice"));
    assert!(!pattern.is_match("alice.dhttp.net"));
}

#[test]
fn client_name_pattern_expands_tilde_to_full_dhttp_suffix() {
    let pattern =
        Pattern::<ClientNamePatternKind>::new("alice~").expect("valid client name pattern");

    assert!(pattern.is_match("alice.dhttp.net"));
    assert!(!pattern.is_match("alice"));
    assert_eq!(pattern.as_str(), "alice.dhttp.net");
}

#[test]
fn client_name_regex_expands_tilde_as_literal_dhttp_suffix() {
    let pattern =
        Pattern::<ClientNamePatternKind>::new("~ ^alice~$").expect("valid client name pattern");

    assert!(pattern.is_match("alice.dhttp.net"));
    assert!(!pattern.is_match("alicexdhttpxnet"));
    assert_eq!(pattern.as_str(), r"~ ^alice\.dhttp\.net$");
}

#[test]
fn client_name_glob_expands_tilde_to_full_dhttp_suffix() {
    let pattern =
        Pattern::<ClientNamePatternKind>::new("*.dong~").expect("valid client glob pattern");

    assert!(pattern.is_match("youmu.dong.dhttp.net"));
    assert!(!pattern.is_match("youmu.dong"));
    assert_eq!(pattern.as_str(), "*.dong.dhttp.net");
}

#[test]
fn client_name_pattern_rejects_unreachable_smart_quotes() {
    let error = Pattern::<ClientNamePatternKind>::new("“*?”").unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(
        rendered.contains("cannot match any valid client name"),
        "error: {rendered}"
    );
}

#[test]
fn location_pattern_rejects_unreachable_regex_smart_quotes() {
    let error = LocationPattern::new("~ “").unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(
        rendered.contains("cannot match any valid location path"),
        "error: {rendered}"
    );
}
