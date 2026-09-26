use Part::*;

use super::*;

fn lex(source: &str) -> TokenStream<'_> {
    let tokens = lexer::tokens(source).unwrap_or_else(|e| panic!("Lex error for `{source}`: {e}"));
    println!(
        "Tokens: {:?}",
        tokens
            .iter()
            .map(|t| t.token.to_string())
            .collect::<Vec<_>>()
    );
    TokenStream { tokens, source }
}

#[test]
#[should_panic(expected = "Lex error")]
fn incomplete_quote() {
    lex(r#" " "#);
}

fn location_invariant(source: &str) -> Exprs<BooleanOperator, AtomicLocationRuleExpr> {
    let exprs = infix_location_rule_exprs(&lex(source))
        .unwrap_or_else(|e| panic!("Parse error for `{source}`: {e}"))
        .unwrap_or_else(|e| panic!("Invalid value for `{source}`: {e}"));

    println!("Location Exprs: {exprs:?}");

    let json = serde_json::to_string(&exprs).unwrap();
    let exprs2 = serde_json::from_str::<Exprs<_, _>>(&json)
        .unwrap_or_else(|e| panic!("(Invariant)Parse error for `{json}`: {e}"));
    assert!(
        exprs2 == exprs,
        "Invariant test failed for `{json}`: got {}",
        serde_json::to_string(&exprs2).unwrap()
    );

    exprs
}

#[test]
fn escape() {
    assert!(matches!(
        &location_invariant( r#" "*.remote" "#)[0],
        Expr(AtomicLocationRuleExpr::ClientName(pattern)) if pattern.as_ref().as_str() == "*.remote"
    ));

    let exprs = location_invariant(r#" *? with header X:"\"remote" "#);
    assert!(matches!(
        &exprs[2],
        Expr(AtomicLocationRuleExpr::Header(header))
            if header.as_ref().key.as_str() == "X"
                && header.as_ref().value.as_str() == r#""remote"#
    ));
}

#[test]
fn any() {
    assert!(matches!(
        &location_invariant("*?")[0],
        Expr(AtomicLocationRuleExpr::Any(AnyClient))
    ));
}

#[test]
fn or() {
    location_invariant(r#" "*.remote" with method ( GET or POST )"#);
}

#[test]
fn not() {
    location_invariant(r#" *? without header H"#);
}

#[test]
fn combine_not() {
    location_invariant(r#" *? with method GET or not header rebot "#);
}

#[test]
fn bracket() {
    location_invariant(r#" *? with method (G*) "#);
}

#[test]
fn combine_patterns() {
    location_invariant(
        r#" "*.example.com" with (header X-User:admin and method LOGIN) or not method "~ GET|PUT|POST|DELETE|CONNECT" "#,
    );
    location_invariant(
        r#" "*.example.com" without (header X-User:admin and method LOGIN) or not method "~ GET|PUT|POST|DELETE|CONNECT" "#,
    );
    location_invariant(
        r#" *? with (header X-User:admin and method LOGIN) or not method "~ GET|PUT|POST|DELETE|CONNECT" "#,
    );
    location_invariant(
        r#" *? without (header X-User:admin and method LOGIN) or not method "~ GET|PUT|POST|DELETE|CONNECT" "#,
    );
}

#[test]
fn keyword() {
    location_invariant(r#" *? with method "not" "#);
    location_invariant(r#" *? with method "method" "#);
}

#[test]
fn client_name_pattern_rejects_unreachable_smart_quotes() {
    let error = "“*?”".parse::<LocationRuleExprs>().unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(rendered.contains("client name"), "error: {rendered}");
    assert!(
        rendered.contains("cannot match any valid client name"),
        "error: {rendered}"
    );
}

#[test]
fn client_name_pattern_expands_shorthand_in_expr() {
    let exprs = "alice~"
        .parse::<LocationRuleExprs>()
        .expect("dhttp shorthand should parse");

    assert_eq!(exprs.to_string(), "alice~");
    assert!(matches!(
        &location_invariant("alice~")[0],
        Expr(AtomicLocationRuleExpr::ClientName(pattern))
            if pattern.as_ref().as_str() == "alice.dhttp.net"
    ));
}

#[test]
fn client_name_pattern_displays_shorthand_for_canonical_name() {
    let exprs = "alice.dhttp.net"
        .parse::<LocationRuleExprs>()
        .expect("canonical dhttp name should parse");

    assert_eq!(exprs.to_string(), "alice~");
}

#[test]
fn method_pattern_rejects_unreachable_space() {
    let error = r#"*? with method "GET POST""#.parse::<LocationRuleExprs>().unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(rendered.contains("HTTP method"), "error: {rendered}");
    assert!(
        rendered.contains("cannot match any valid HTTP method"),
        "error: {rendered}"
    );
}

#[test]
fn query_key_pattern_rejects_split_delimiter() {
    let error = r#"*? with query "= =""#.parse::<LocationRuleExprs>().unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(rendered.contains("query key"), "error: {rendered}");
    assert!(
        rendered.contains("cannot match any valid query key"),
        "error: {rendered}"
    );
}

#[test]
fn query_value_pattern_rejects_pair_delimiter() {
    let error = r#"*? with query q:"= a&b""#.parse::<LocationRuleExprs>().unwrap_err();
    let rendered = snafu::Report::from_error(error).to_string();

    assert!(rendered.contains("query value"), "error: {rendered}");
    assert!(
        rendered.contains("cannot match any valid query value"),
        "error: {rendered}"
    );
}

#[test]
#[should_panic]
fn keyword_panic() {
    location_invariant(r#" *? with header "X-Pasword" "and" X-User "#);
}
