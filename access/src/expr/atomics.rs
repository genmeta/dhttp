#![allow(deprecated)]

use std::{fmt::Display, net::IpAddr, str::FromStr};

use derive_more::{AsRef, Display, From, Into};
use snafu::OptionExt;

use crate::{
    action::RequestAction,
    expr::{
        eval::{EvalRuleError, Evaluable},
        parse::{self, InvalidPatternExpr},
    },
    pattern::{ClientNamePattern, NormalPattern, Pattern},
};

/// 表示网络请求的源类型
#[deprecated = "Redesign in the future"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// 本地网络（LAN）
    Lan,
    /// 广域网络（WAN）
    Wan,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Lan => "lan",
            Source::Wan => "wan",
        }
    }

    /// 判断IP地址是否匹配当前源类型
    ///
    /// ```
    /// use dhttp_access::expr::atomics::Source;
    ///
    /// let lan = Source::Lan;
    /// let wan = Source::Wan;
    ///
    /// // LAN 地址
    /// assert!(lan.is_match("192.168.1.1".parse().unwrap()));
    /// assert!(lan.is_match("10.0.0.1".parse().unwrap()));
    /// assert!(lan.is_match("::1".parse().unwrap()));
    ///
    /// // WAN 地址
    /// assert!(wan.is_match("8.8.8.8".parse().unwrap()));
    /// assert!(wan.is_match("2001:4860:4860::8888".parse().unwrap()));
    ///
    /// // 交叉验证
    /// assert!(!lan.is_match("8.8.8.8".parse().unwrap()));
    /// assert!(!wan.is_match("192.168.1.1".parse().unwrap()));
    /// ```
    pub fn is_match(&self, source: IpAddr) -> bool {
        let source_is_lan = match source {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        (self == &Self::Lan) == source_is_lan
    }
}

impl Evaluable<IpAddr> for Source {
    type Value = bool;

    fn eval(&self, argument: &IpAddr) -> Self::Value {
        self.is_match(*argument)
    }
}

impl Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnyClient;

impl Evaluable<Option<&str>> for AnyClient {
    type Value = bool;

    fn eval(&self, _: &Option<&str>) -> Self::Value {
        true
    }
}

impl Display for AnyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "*?".fmt(f)
    }
}

#[derive(snafu::Snafu, Debug, Clone, Copy)]
pub enum EvalError {
    #[snafu(display("client name is not provided, cannot match client name pattern"))]
    MissingClientName,
}

impl EvalRuleError<RequestAction> for EvalError {
    fn fallback(&self, matched_action: RequestAction) -> Option<RequestAction> {
        _ = matched_action;
        Some(RequestAction::Deny)
    }
}

#[derive(Debug, Display, Clone, From, Into, AsRef, PartialEq, Eq)]
pub struct ClientName(ClientNamePattern);

impl Evaluable<Option<&str>> for ClientName {
    type Value = Result<bool, EvalError>;

    fn eval(&self, argument: &Option<&str>) -> Self::Value {
        argument
            .map(|client_name| self.0.eval(&client_name))
            .context(MissingClientNameSnafu)
    }
}

#[derive(Debug, Clone, From, Into, AsRef, PartialEq, Eq)]
pub struct Method {
    pattern: NormalPattern,
}

#[cfg(feature = "http")]
impl Evaluable<&http::Method> for Method {
    type Value = bool;

    fn eval(&self, method: &&http::Method) -> Self::Value {
        self.pattern.eval(&method.as_str())
    }
}

/// 键值对模式，用于匹配HTTP头或查询参数
///
/// TODO: 支持key的匹配项参与匹配?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KVPattern {
    pub key: NormalPattern,
    pub value: NormalPattern,
}

impl Evaluable<(&str, &str)> for KVPattern {
    type Value = bool;

    fn eval(&self, (key, value): &(&str, &str)) -> Self::Value {
        self.key.eval(key) && self.value.eval(value)
    }
}

impl Display for KVPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.key, self.value)
    }
}

#[derive(Debug, Clone, From, Into, AsRef, PartialEq, Eq)]
pub struct Header {
    pattern: KVPattern,
}

impl Evaluable<(&str, &str)> for Header {
    type Value = bool;

    fn eval(&self, pair: &(&str, &str)) -> Self::Value {
        self.pattern.eval(pair)
    }
}

#[cfg(feature = "http")]
impl Evaluable<(&http::HeaderName, &http::HeaderValue)> for Header {
    type Value = bool;

    fn eval(&self, (key, value): &(&http::HeaderName, &http::HeaderValue)) -> Self::Value {
        let Ok(value) = value.to_str() else {
            // TODO: support binary header value match
            return false;
        };
        self.eval(&(key.as_str(), value))
    }
}

#[derive(Debug, Clone, From, Into, AsRef, PartialEq, Eq)]
pub struct Query {
    pattern: KVPattern,
}

impl Evaluable<(&str, &str)> for Query {
    type Value = bool;

    fn eval(&self, pair: &(&str, &str)) -> Self::Value {
        self.pattern.eval(pair)
    }
}

fn escape_pattern<Kind>(pat: &Pattern<Kind>) -> String {
    pat.as_str().replace('\\', "\\\\").replace('"', "\\\"")
}

fn to_quoted_escaped_pattern<Kind>(pat: &Pattern<Kind>) -> String {
    format!("\"{}\"", escape_pattern(pat))
}

fn to_quoted_escaped_kv_pattern(pat: &KVPattern) -> String {
    let KVPattern { key, value } = pat;
    let (key, value) = (escape_pattern(key), escape_pattern(value));
    format!("\"{}\":\"{}\"", key, value)
}

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
