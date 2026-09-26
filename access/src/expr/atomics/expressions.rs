#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicLocationRuleExpr {
    Any(AnyClient), // "*?"
    ClientName(ClientName),
    Method(Method),
    Header(Header),
    Query(Query),
}

impl Display for AtomicLocationRuleExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any(any) => any.fmt(f),
            Self::ClientName(pattern) => {
                write!(f, "{}", to_quoted_escaped_pattern(pattern.as_ref()))
            }
            Self::Method(Method { pattern }) => {
                write!(f, "With Method {}", to_quoted_escaped_pattern(pattern))
            }
            Self::Header(Header { pattern }) => {
                write!(f, "With Header {}", to_quoted_escaped_kv_pattern(pattern))
            }
            Self::Query(Query { pattern }) => {
                write!(f, "With Query {}", to_quoted_escaped_kv_pattern(pattern))
            }
        }
    }
}

mod parse_atomic {

    use peg::{error::ParseError, str::LineCol};
    use snafu::ResultExt;

    use super::*;

    #[derive(snafu::Snafu, Debug)]
    pub enum ParseAtomicRuleExprError {
        #[snafu(display("failed to parse rule expr"))]
        Pattern { source: InvalidPatternExpr },
        #[snafu(display("failed to parse rule expr `{input}`"))]
        Incomplete {
            input: String,
            source: ParseError<LineCol>,
        },
    }

    impl FromStr for AtomicLocationRuleExpr {
        type Err = ParseAtomicRuleExprError;

        fn from_str(infix: &str) -> Result<Self, Self::Err> {
            let tokens =
                parse::TokenStream::new(infix).context(IncompleteSnafu { input: infix })?;
            parse::atomic_location_rule_expr(&tokens)
                .context(IncompleteSnafu { input: infix })?
                .context(PatternSnafu)
        }
    }
}

#[cfg(feature = "http")]
pub struct HttpRequest<'a> {
    client_name: Option<&'a str>,
    method: &'a http::Method,
    headers: &'a http::HeaderMap<http::HeaderValue>,
    queries: Vec<(&'a str, &'a str)>,
}

#[cfg(feature = "http")]
impl<'a> HttpRequest<'a> {
    pub fn new<T>(client_name: Option<&'a str>, request: &'a http::Request<T>) -> Self {
        Self {
            client_name,
            method: request.method(),
            headers: request.headers(),
            queries: request.uri().query().map_or(vec![], |q| {
                q.split('&')
                    .filter_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        let key = parts.next()?;
                        let value = parts.next().unwrap_or("");
                        Some((key, value))
                    })
                    .collect::<Vec<(&str, &str)>>()
            }),
        }
    }
}

#[cfg(feature = "http")]
impl Evaluable<HttpRequest<'_>> for AtomicLocationRuleExpr {
    type Value = Result<bool, EvalError>;

    fn eval(&self, request: &HttpRequest) -> Self::Value {
        Ok(match self {
            // Self::Source(source) => source.eval(&argument.source_ip),
            Self::Any(..) => true,
            Self::ClientName(pattern) => pattern.eval(&request.client_name)?,
            Self::Method(method) => method.eval(&request.method),
            Self::Header(header) => request.headers.iter().any(|(k, v)| header.eval(&(k, v))),
            Self::Query(query) => request.queries.iter().any(|pair| query.eval(pair)),
        })
    }
}
