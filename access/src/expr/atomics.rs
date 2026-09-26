#![allow(deprecated)]

use std::{fmt::Display, net::IpAddr, str::FromStr};

use derive_more::{AsRef, Display, Into};
use snafu::OptionExt;

use crate::{
    action::RequestAction,
    expr::{
        eval::{EvalRuleError, Evaluable},
        parse::{self, InvalidPatternExpr},
    },
    pattern::{
        ClientNamePattern, NormalPattern, Pattern,
        reachability::{
            ClientNameLanguage, HeaderNameLanguage, HeaderValueLanguage, HttpMethodLanguage,
            PatternInputLanguage, QueryKeyLanguage, QueryValueLanguage, ReachabilityError,
            validate_reachable,
        },
    },
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

#[derive(snafu::Snafu, Debug)]
#[snafu(module)]
pub enum BuildAtomicPatternError {
    #[snafu(display("invalid {domain} pattern"))]
    Unreachable {
        domain: &'static str,
        source: ReachabilityError,
    },
}

#[derive(Debug, Display, Clone, Into, AsRef, PartialEq, Eq)]
pub struct ClientName(ClientNamePattern);

impl ClientName {
    pub fn new(pattern: ClientNamePattern) -> Result<Self, BuildAtomicPatternError> {
        validate_reachable::<_, ClientNameLanguage>(&pattern).map_err(|source| {
            BuildAtomicPatternError::Unreachable {
                domain: "client name",
                source,
            }
        })?;
        Ok(Self(pattern))
    }
}

impl Evaluable<Option<&str>> for ClientName {
    type Value = Result<bool, EvalError>;

    fn eval(&self, argument: &Option<&str>) -> Self::Value {
        argument
            .map(|client_name| self.0.eval(&client_name))
            .context(MissingClientNameSnafu)
    }
}

#[derive(Debug, Clone, Into, AsRef, PartialEq, Eq)]
pub struct Method {
    pattern: NormalPattern,
}

impl Method {
    pub fn new(pattern: NormalPattern) -> Result<Self, BuildAtomicPatternError> {
        validate_reachable::<_, HttpMethodLanguage>(&pattern).map_err(|source| {
            BuildAtomicPatternError::Unreachable {
                domain: "HTTP method",
                source,
            }
        })?;
        Ok(Self { pattern })
    }
}

#[cfg(feature = "http")]
impl Evaluable<&http::Method> for Method {
    type Value = bool;

    fn eval(&self, method: &&http::Method) -> Self::Value {
        self.pattern.eval(&method.as_str())
    }
}

include!("atomics/pairs.rs");
include!("atomics/expressions.rs");
