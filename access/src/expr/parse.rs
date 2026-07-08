use std::{fmt::Display, str::FromStr};

use peg::{error::ParseError, str::LineCol};
use snafu::ResultExt;

use crate::{
    expr::{atomics::*, eval::*, exprs::*},
    pattern::{ClientNamePattern, NormalPattern, ParsePatternError},
};

pub enum Token<'t> {
    Unquoted(&'t str),
    Quoted(String),
    Symbol(char),
}

impl<'t> Token<'t> {
    pub fn len(&self) -> usize {
        match self {
            Token::Unquoted(s) => s.len(),
            Token::Quoted(cow) => cow.len(),
            Token::Symbol(c) => c.len_utf8(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Display for Token<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Unquoted(s) => s.fmt(f),
            Token::Quoted(cow) => cow.fmt(f),
            Token::Symbol(c) => c.fmt(f),
        }
    }
}

pub struct PositionedToken<'t> {
    token: Token<'t>,
    position: usize,
}

impl PartialEq<str> for Token<'_> {
    fn eq(&self, other: &str) -> bool {
        match self {
            Token::Unquoted(lit) => lit.eq_ignore_ascii_case(other),
            Token::Quoted(lit) => lit.eq_ignore_ascii_case(other),
            Token::Symbol(c) => c.len_utf8() == other.len() && other.starts_with(*c),
        }
    }
}

pub struct TokenStream<'t> {
    source: &'t str,
    tokens: Vec<PositionedToken<'t>>,
}

impl peg::Parse for TokenStream<'_> {
    type PositionRepr = LineCol;

    fn start(&self) -> usize {
        0
    }

    fn is_eof(&self, p: usize) -> bool {
        p >= self.tokens.len()
    }

    fn position_repr(&self, p: usize) -> Self::PositionRepr {
        let start = LineCol {
            line: 1,
            column: 1,
            offset: 0,
        };
        if p >= self.tokens.len() {
            self.tokens.last().map_or(start, |t| {
                str::position_repr(self.source, t.position + t.token.len())
            })
        } else {
            str::position_repr(self.source, self.tokens[p].position)
        }
    }
}

impl<'input> peg::ParseElem<'input> for TokenStream<'input> {
    type Element = &'input Token<'input>;

    fn parse_elem(&'input self, pos: usize) -> peg::RuleResult<Self::Element> {
        match pos < self.tokens.len() {
            true => peg::RuleResult::Matched(pos + 1, &self.tokens[pos].token),
            false => peg::RuleResult::Failed,
        }
    }
}

impl<'input> peg::ParseLiteral for TokenStream<'input> {
    fn parse_string_literal(&self, pos: usize, literal: &str) -> peg::RuleResult<()> {
        match self.tokens.get(pos) {
            Some(PositionedToken { token, .. }) if token == literal => {
                peg::RuleResult::Matched(pos + 1, ())
            }
            _ => peg::RuleResult::Failed,
        }
    }
}

impl<'input> peg::ParseSlice<'input> for TokenStream<'input> {
    type Slice = &'input [PositionedToken<'input>];

    fn parse_slice(&'input self, p1: usize, p2: usize) -> Self::Slice {
        &self.tokens[p1..p2]
    }
}

peg::parser! {
    grammar lexer() for str {
        rule quoted_char() -> char =
            quiet! {
                // escape
                "\\\"" { '"' } /
                "\\\\" { '\\' } /
                // end with "
                c:[^ '"'] { c }
            } / expected!("any character")

        rule quoted_string() -> String =
            "\"" chars:quoted_char()* ( quiet! { "\"" } / expected!("end quote") ) { chars.into_iter().collect() }

        rule unquoted_string() -> &'input str =
            s:$([^c if c.is_whitespace() || matches!(c, ':' | '(' | ')' | '"')]+) { s }

        rule string() -> PositionedToken<'input> =
            position:position!() string:quoted_string()  {
                PositionedToken { token: Token::Quoted(string), position }
            } /
            position:position!() string:unquoted_string() {
                PositionedToken { token: Token::Unquoted(string), position }
            }

        rule symbol() -> PositionedToken<'input> =
            position:position!() c:$(['(' | ')' | ':']) {
                PositionedToken { token: Token::Symbol(c.chars().next().unwrap()), position }
            }

        rule token() -> PositionedToken<'input> =
            string() / symbol()

        rule _() = [c if c.is_whitespace()]*

        pub rule tokens() -> Vec<PositionedToken<'input>> =
            _ tokens:(token() ** _) _ { tokens }
    }
}

impl<'t> TokenStream<'t> {
    pub fn new(source: &'t str) -> Result<Self, ParseError<LineCol>> {
        let tokens = lexer::tokens(source)?;
        Ok(TokenStream { source, tokens })
    }
}

mod utils {

    use super::*;

    #[derive(snafu::Snafu, Debug)]
    #[snafu(visibility(pub))]
    pub enum InvalidPatternExpr {
        #[snafu(display("invalid value for `{expr}`: invalid pattern"))]
        Pattern {
            expr: &'static str,
            source: ParsePatternError,
        },
        #[snafu(display("invalid value for `{expr}`: invalid pattern"))]
        Atomic {
            expr: &'static str,
            source: BuildAtomicPatternError,
        },
    }

    pub type Result<T, E = InvalidPatternExpr> = core::result::Result<T, E>;

    pub fn chain2<C, T>(c1: impl IntoIterator<Item = T>, c2: impl IntoIterator<Item = T>) -> C
    where
        C: FromIterator<T>,
    {
        c1.into_iter().chain(c2).collect()
    }

    pub fn chain3<C, T>(
        c1: impl IntoIterator<Item = T>,
        c2: impl IntoIterator<Item = T>,
        c3: impl IntoIterator<Item = T>,
    ) -> C
    where
        C: FromIterator<T>,
    {
        c1.into_iter().chain(c2).chain(c3).collect()
    }
}

pub use utils::InvalidPatternExpr;

peg::parser! {
    grammar parser<'t>() for TokenStream<'t> {
        use utils::*;
        use BooleanOperator::*;
        use Part::*;
        use Token::*;
        use peg::error::ErrorState;
        use peg::RuleResult;

        rule i(literal: &'static str) =
            quiet!{
                [Unquoted(l) if l.eq_ignore_ascii_case(literal)] /
                [Quoted(l)   if l.eq_ignore_ascii_case(literal)]
            } / expected!(literal)

        rule ikeyword(literal: &'static str) =
            quiet!{ [Unquoted(l) if l.eq_ignore_ascii_case(literal)] } /
            expected!(literal)

        // 由于expected的限制，只能使用str
        rule s(symbol: &'static str) =
            quiet!{ [token @ Symbol(..) if token == symbol ] } / expected!(symbol)

        rule bracketed<T>(r: rule<T>) -> T = s("(") x:r() s(")") { x }

        // pub rule source() -> Source =
        //     i("wan") { Source::Wan } /
        //     i("lan") { Source::Lan } /
        //     expected!("`lan` or `wan`")

        rule any() = ikeyword("*?")

        // rule append_suffix_pattern(suffix: &'static str) -> Result<NormalPattern, ParsePatternError> =
        //     token:( quiet!{ [Quoted(l)] } / quiet!{ [Unquoted(l)] } / expected!("pattern")) { match token {
        //         Quoted(lit) if suffix.is_empty() => NormalPattern::from_str(lit),
        //         Quoted(lit) => NormalPattern::from_str(format!("{lit}{suffix}").as_str()),
        //         Unquoted(lit) if suffix.is_empty() => NormalPattern::from_str(lit),
        //         Unquoted(lit) => NormalPattern::from_str(format!("{lit}{suffix}").as_str()),
        //         _ => unreachable!(),
        //     } }

        rule pattern() -> Result<NormalPattern, ParsePatternError> =
            token:( quiet!{ [Quoted(l)] } / quiet!{ [Unquoted(l)] } / expected!("pattern")) { match token {
                Quoted(lit) => NormalPattern::from_str(lit),
                Unquoted(lit) => NormalPattern::from_str(lit),
                _ => unreachable!(),
            } }

        rule pattern_expr(expr: &'static str) -> Result<NormalPattern> =
            pattern:pattern() { pattern.context(PatternSnafu { expr }) }

        rule client_name_pattern() -> Result<ClientNamePattern> =
            pattern:pattern_expr("client_name_pattern") {
                pattern.and_then(|pattern| {
                    ClientNamePattern::from_str(pattern.as_str())
                        .context(PatternSnafu { expr: "client_name_pattern" })
                })
            }

        rule client_name() -> Result<ClientName> = pattern:client_name_pattern() {
            pattern.and_then(|pattern| ClientName::new(pattern).context(AtomicSnafu { expr: "client_name_pattern" }))
        }

        rule and() = ikeyword("and")
        rule or()  = ikeyword("or")
        rule not() = ikeyword("not")

        rule method_pattern() -> Result<Method> =
            pattern:pattern_expr("method_pattern") {
                pattern.and_then(|pattern| Method::new(pattern).context(AtomicSnafu { expr: "method_pattern" }))
            }

        rule method() -> Result<AtomicLocationRuleExpr> =
            ikeyword("method") method:method_pattern() { method.map(AtomicLocationRuleExpr::Method) }

        rule kv_pattern() -> Result<KVPattern, ParsePatternError> =
            key:pattern() s(":") value:pattern() {
                Ok(KVPattern { key: key?, value: value? })
            } /
            key:pattern() {
                Ok(KVPattern { key: key?, value: NormalPattern::new("*")? })
            }

        rule kv_pattern_expr(key: &'static str, value: &'static str) -> Result<KVPattern> =
            key:pattern_expr(key) ":" value:pattern_expr(value) {
                Ok(KVPattern { key: key?, value: value? })
            } /
            key:pattern_expr(key) {
                let value = NormalPattern::new("*").context(PatternSnafu { expr: value })?;
                Ok(KVPattern { key: key?, value })
            }

        rule header_pattern() -> Result<Header> =
            pattern:kv_pattern_expr("header_key", "header_value") {
                pattern.and_then(|pattern| {
                    let KVPattern { key, value } = pattern;
                    KVPattern::new_header(key, value)
                        .map(Header::new)
                        .context(AtomicSnafu { expr: "header_pattern" })
                })
            }

        rule header() -> Result<AtomicLocationRuleExpr> =
            i("header") header:header_pattern() { header.map(AtomicLocationRuleExpr::Header) }

        rule query_pattern() -> Result<Query> =
            pattern:kv_pattern_expr("query_key", "query_value") {
                pattern.and_then(|pattern| {
                    let KVPattern { key, value } = pattern;
                    KVPattern::new_query(key, value)
                        .map(Query::new)
                        .context(AtomicSnafu { expr: "query_pattern" })
                })
            }

        rule query() -> Result<AtomicLocationRuleExpr> =
            ikeyword("query") query:query_pattern() { query.map(AtomicLocationRuleExpr::Query) }

        pub rule atomic_location_rule_expr() -> Result<AtomicLocationRuleExpr> =
            any() { Ok(AtomicLocationRuleExpr::Any(AnyClient)) } /
            ikeyword("with") with:( header() / query() / method()) { with } /
            pattern:client_name(){ Ok(AtomicLocationRuleExpr::ClientName(pattern?)) }

        rule location_rule_expr_part() -> Result<Part<BooleanOperator, AtomicLocationRuleExpr>> =
            not() { Ok(Operator(Not)) } /
            and() { Ok(Operator(And)) } /
            or()  { Ok(Operator(Or )) } /
            atomic:atomic_location_rule_expr() { Ok(Expr(atomic?)) }

        pub rule polish_location_rule_exprs() -> Result<Exprs<BooleanOperator, AtomicLocationRuleExpr>> =
            exprs:(location_rule_expr_part())* { exprs.into_iter().collect() }

        rule composite<E, T, R>(r: R) -> Result<Exprs<BooleanOperator, E>>
        where
            Exprs<BooleanOperator, E>: From<T>,
            R: Clone + Fn(&'input TokenStream<'t>, &mut ParseState<'input, 't>, &mut ErrorState, usize) -> RuleResult<Result<T>>
        = precedence! {
            x:(@) and() y:@ { Ok(chain3([Operator(And)], x?, y?)) }
            x:(@) or()  y:@ { Ok(chain3([Operator(Or )], x?, y?)) }
            --
            not() x:(@) { Ok(chain2([Operator(Not)], x?)) }
            --
            exprs:r() { Ok(exprs?.into()) }
            exprs:bracketed(<composite(r.clone())>) { exprs }
        }

        rule bracketed_composite_or_atomic<E, T, R>(r: R) -> Result<Exprs<BooleanOperator, E>>
        where
            Exprs<BooleanOperator, E>: From<T>,
            R: Clone + Fn(&'input TokenStream<'t>, &mut ParseState<'input, 't>, &mut ErrorState, usize) -> RuleResult<Result<T>>
        = exprs:bracketed(<composite(<r()>)>) { exprs } / atomic:r() { Ok(atomic?.into()) }

        rule possiable_negative_expr<E, T>(r: rule<Result<T>>) -> Result<Exprs<BooleanOperator, E>>
        where
            Exprs<BooleanOperator, E>: From<T>,
        = not() exprs:r() { Ok(chain2([Operator(Not)], Exprs::from(exprs?))) } / exprs:r() { Ok(exprs?.into()) }

        rule location_patterns() -> Result<Exprs<BooleanOperator, AtomicLocationRuleExpr>> =
            ikeyword("header") exprs:bracketed_composite_or_atomic(<pat: header_pattern() { pat.map(AtomicLocationRuleExpr::Header).map(Expr) }>) { exprs } /
            ikeyword("query")  exprs:bracketed_composite_or_atomic(<pat: query_pattern()  { pat.map(AtomicLocationRuleExpr::Query).map(Expr)  }>) { exprs } /
            // method not 很合理
            ikeyword("method") exprs:bracketed_composite_or_atomic(<possiable_negative_expr(<pat: method_pattern() { pat.map(AtomicLocationRuleExpr::Method).map(Expr) }>)>) { exprs }

        rule with<T>(r: rule<Result<Exprs<BooleanOperator, T>>>) -> Result<Exprs<BooleanOperator, T>> =
            ikeyword("with")    exprs:r() { exprs } /
            ikeyword("without") exprs:r() { Ok(chain2([Operator(Not)], exprs?)) }

        rule location_profile() -> Result<AtomicLocationRuleExpr> =
            any() { Ok(AtomicLocationRuleExpr::Any(AnyClient)) } /
            pattern:client_name() { Ok(AtomicLocationRuleExpr::ClientName(pattern?)) }

        pub rule infix_location_rule_exprs() -> Result<Exprs<BooleanOperator, AtomicLocationRuleExpr>> =
            profile:location_profile() patterns:with(<composite(<location_patterns()>)>)? {
                match patterns {
                   Some(patterns) => Ok(chain3([Operator(And)], [profile.map(Expr)?], patterns?)),
                   None => Ok(profile.map(Expr)?.into()),
                }
            }
    }
}

pub use parser::*;

#[cfg(test)]
mod tests {
    use Part::*;

    use super::*;

    fn lex(source: &str) -> TokenStream<'_> {
        let tokens =
            lexer::tokens(source).unwrap_or_else(|e| panic!("Lex error for `{source}`: {e}"));
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

        assert_eq!(exprs.to_string(), "alice.dhttp.net");
        assert!(matches!(
            &location_invariant("alice~")[0],
            Expr(AtomicLocationRuleExpr::ClientName(pattern))
                if pattern.as_ref().as_str() == "alice.dhttp.net"
        ));
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
}
