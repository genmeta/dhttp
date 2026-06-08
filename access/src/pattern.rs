use std::{fmt::Display, str::FromStr, sync::Arc};

use derive_more::{AsRef, From, Into};
use dhttp_identity::name::DhttpName;
use regex::{Error as RegexError, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::expr::eval::Evaluable;

/// 普通模式类型，支持精确匹配、Glob模式和正则表达式
///
/// # 示例
///
/// ```
/// use dhttp_access::pattern::{NormalPattern, NormalPatternKind};
///
/// // 精确匹配
/// let pattern: NormalPattern = "= hello".parse().unwrap();
/// assert_eq!(pattern.kind(), &NormalPatternKind::Exact);
/// assert!(pattern.is_match("hello"));
/// assert!(!pattern.is_match("hello world"));
///
/// // Glob 模式（默认）
/// let pattern: NormalPattern = "*.txt".parse().unwrap();
/// assert_eq!(pattern.kind(), &NormalPatternKind::Glob);
/// assert!(pattern.is_match("file.txt"));
/// assert!(!pattern.is_match("file.doc"));
///
/// // Glob 模式（不区分大小写）
/// let pattern: NormalPattern = "* *.TXT".parse().unwrap();
/// assert_eq!(pattern.kind(), &NormalPatternKind::Glob);
/// assert!(pattern.is_match("file.txt"));
/// assert!(pattern.is_match("FILE.TXT"));
///
/// // 正则表达式
/// let pattern: NormalPattern = r"~ \d+".parse().unwrap();
/// assert_eq!(pattern.kind(), &NormalPatternKind::Regex);
/// assert!(pattern.is_match("123"));
/// assert!(!pattern.is_match("abc"));
///
/// // 正则表达式（不区分大小写）
/// let pattern: NormalPattern = "~* hello".parse().unwrap();
/// assert_eq!(pattern.kind(), &NormalPatternKind::Regex);
/// assert!(pattern.is_match("HELLO"));
/// assert!(pattern.is_match("hello"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NormalPatternKind {
    /// 精确匹配模式 - 语法：`= pattern`
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{NormalPattern, NormalPatternKind};
    ///
    /// let pattern: NormalPattern = "= hello".parse().unwrap();
    /// assert!(matches!(pattern.kind(), NormalPatternKind::Exact));
    /// assert!(pattern.is_match("hello"));
    /// assert!(!pattern.is_match("Hello"));
    /// assert!(!pattern.is_match("hello world"));
    /// ```
    Exact = 0,
    /// Glob 模式匹配 - 语法：`pattern` (默认) 或 `* pattern` (不区分大小写)
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{NormalPattern, NormalPatternKind};
    ///
    /// // 默认 glob 模式
    /// let pattern: NormalPattern = "*.txt".parse().unwrap();
    /// assert!(matches!(pattern.kind(), NormalPatternKind::Glob));
    /// assert!(pattern.is_match("test.txt"));
    /// assert!(pattern.is_match("hello.txt"));
    /// assert!(!pattern.is_match("test.doc"));
    ///
    /// // 不区分大小写的 glob 模式
    /// let pattern: NormalPattern = "* *.TXT".parse().unwrap();
    /// assert!(pattern.is_match("test.txt"));
    /// assert!(pattern.is_match("TEST.TXT"));
    /// ```
    Glob = 1,
    /// 正则表达式匹配 - 语法：`~ regex` 或 `~* regex` (不区分大小写)
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{NormalPattern, NormalPatternKind};
    ///
    /// // 区分大小写的正则
    /// let pattern: NormalPattern = "~ test\\d+".parse().unwrap();
    /// assert!(matches!(pattern.kind(), NormalPatternKind::Regex));
    /// assert!(pattern.is_match("test123"));
    /// assert!(!pattern.is_match("Test123"));
    ///
    /// // 不区分大小写的正则
    /// let pattern: NormalPattern = "~* test\\d+".parse().unwrap();
    /// assert!(pattern.is_match("test123"));
    /// assert!(pattern.is_match("Test123"));
    /// assert!(pattern.is_match("TEST123"));
    /// ```
    Regex = 2,
}

impl NormalPatternKind {
    const fn priority(&self) -> usize {
        *self as usize
    }
}

#[derive(
    Debug, Clone, Copy, From, Into, AsRef, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ClientNamePatternKind(NormalPatternKind);

impl ClientNamePatternKind {
    const fn priority(&self) -> usize {
        self.0.priority()
    }
}

#[derive(
    Debug, Clone, Copy, From, Into, AsRef, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct DomainPatternKind(NormalPatternKind);

impl DomainPatternKind {
    const fn priority(&self) -> usize {
        self.0.priority()
    }
}

/// 位置模式类型，类似 Nginx location 配置
///
/// # 示例
///
/// ```
/// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
///
/// // 精确匹配
/// let pattern: LocationPattern = "= /api/v1".parse().unwrap();
/// assert_eq!(pattern.kind(), &LocationPatternKind::Exact);
/// assert!(pattern.is_match("/api/v1"));
/// assert!(!pattern.is_match("/api/v1/users"));
///
/// // 字面量前缀匹配
/// let pattern: LocationPattern = "^~ /static/".parse().unwrap();
/// assert_eq!(pattern.kind(), &LocationPatternKind::Prefix);
/// assert!(pattern.is_match("/static/css/style.css"));
/// assert!(!pattern.is_match("/images/logo.png"));
///
/// // 正则表达式匹配
/// let pattern: LocationPattern = r"~ ^/api/\d+$".parse().unwrap();
/// assert_eq!(pattern.kind(), &LocationPatternKind::Regex);
/// assert!(pattern.is_match("/api/123"));
/// assert!(!pattern.is_match("/api/abc"));
///
/// // 普通前缀匹配
/// let pattern: LocationPattern = "/uploads".parse().unwrap();
/// assert_eq!(pattern.kind(), &LocationPatternKind::NormalPrefix);
/// assert!(pattern.is_match("/uploads/file.jpg"));
///
/// // 通用匹配（根路径）
/// let pattern: LocationPattern = "/".parse().unwrap();
/// assert_eq!(pattern.kind(), &LocationPatternKind::Common);
/// assert!(pattern.is_match("/anything"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LocationPatternKind {
    /// 精确匹配 - 语法：`= pattern`
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
    ///
    /// let pattern: LocationPattern = "= /home".parse().unwrap();
    /// assert!(matches!(pattern.kind(), LocationPatternKind::Exact));
    /// assert!(pattern.is_match("/home"));
    /// assert!(!pattern.is_match("/home/"));
    /// assert!(!pattern.is_match("/home/user"));
    /// ```
    Exact = 0,
    /// 字面量前缀匹配 - 语法：`^~ pattern`
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
    ///
    /// let pattern: LocationPattern = "^~ /api".parse().unwrap();
    /// assert!(matches!(pattern.kind(), LocationPatternKind::Prefix));
    /// assert!(pattern.is_match("/api"));
    /// assert!(pattern.is_match("/api/"));
    /// assert!(pattern.is_match("/api/users"));
    /// assert!(!pattern.is_match("/app"));
    /// ```
    Prefix = 1,
    /// 正则表达式匹配 - 语法：`~ regex` 或 `~* regex` (不区分大小写)
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
    ///
    /// // 区分大小写的正则
    /// let pattern: LocationPattern = "~ /api/\\d+".parse().unwrap();
    /// assert!(matches!(pattern.kind(), LocationPatternKind::Regex));
    /// assert!(pattern.is_match("/api/123"));
    /// assert!(!pattern.is_match("/API/123"));
    ///
    /// // 不区分大小写的正则
    /// let pattern: LocationPattern = "~* /api/\\d+".parse().unwrap();
    /// assert!(pattern.is_match("/api/123"));
    /// assert!(pattern.is_match("/API/123"));
    /// ```
    Regex = 2,
    /// 普通前缀匹配 - 语法：`/xxx` (以 / 开头的路径)
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
    ///
    /// let pattern: LocationPattern = "/admin".parse().unwrap();
    /// assert!(matches!(pattern.kind(), LocationPatternKind::NormalPrefix));
    /// assert!(pattern.is_match("/admin"));
    /// assert!(pattern.is_match("/admin/"));
    /// assert!(pattern.is_match("/admin/users"));
    /// assert!(!pattern.is_match("/app"));
    /// ```
    NormalPrefix = 3,
    /// 通用匹配 - 语法：`/` (根路径)
    ///
    /// # Examples
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, LocationPatternKind};
    ///
    /// let pattern: LocationPattern = "/".parse().unwrap();
    /// assert!(matches!(pattern.kind(), LocationPatternKind::Common));
    /// assert!(pattern.is_match("/"));
    /// assert!(pattern.is_match("/anything"));
    /// assert!(pattern.is_match("/deeply/nested/path"));
    /// ```
    Common = 4,
}

impl LocationPatternKind {
    const fn priority(&self) -> usize {
        *self as usize
    }
}

/// 通用模式匹配结构
///
/// 支持泛型的模式类型，可以用于不同场景的模式匹配。
///
/// # 示例
///
/// ```
/// use dhttp_access::pattern::{NormalPattern, LocationPattern};
///
/// // 普通模式
/// let pattern: NormalPattern = "*.log".parse().unwrap();
/// assert!(pattern.is_match("app.log"));
/// assert_eq!(pattern.as_str(), "*.log");
///
/// // 位置模式
/// let pattern: LocationPattern = "/api".parse().unwrap();
/// assert!(pattern.is_match("/api/users"));
/// assert_eq!(pattern.as_str(), "/api");
///
/// // 匹配子字符串
/// let pattern: NormalPattern = "~ test".parse().unwrap();
/// assert_eq!(pattern.r#match("this is a test"), Some("test"));
/// ```
#[derive(Debug, Clone)]
pub struct Pattern<Kind> {
    kind: Kind,
    regex: Regex,
    pattern: Arc<str>,
}

/// 普通模式类型别名
pub type NormalPattern = Pattern<NormalPatternKind>;

/// 位置模式类型别名
pub type LocationPattern = Pattern<LocationPatternKind>;

pub type ClientNamePattern = Pattern<ClientNamePatternKind>;

pub type DomainPattern = Pattern<DomainPatternKind>;

impl<Kind> Pattern<Kind> {
    /// 创建新的模式实例
    ///
    /// # 示例
    ///
    /// ```
    /// use dhttp_access::pattern::NormalPattern;
    ///
    /// let pattern = NormalPattern::new("*.txt").unwrap();
    /// assert!(pattern.is_match("file.txt"));
    /// ```
    #[inline]
    pub fn new(pattern: impl AsRef<str>) -> Result<Self, <Self as FromStr>::Err>
    where
        Self: FromStr,
    {
        pattern.as_ref().parse()
    }

    /// 获取原始模式字符串
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// 获取模式类型
    #[inline]
    pub const fn kind(&self) -> &Kind {
        &self.kind
    }
}

impl Pattern<NormalPatternKind> {
    /// 测试字符串是否匹配模式
    #[inline]
    pub fn is_match(&self, s: &str) -> bool {
        self.regex.is_match(s)
    }

    /// 获取匹配的子字符串
    #[inline]
    pub fn r#match<'s>(&self, s: &'s str) -> Option<&'s str> {
        self.regex.find(s).map(|m| &s[m.range()])
    }
}

impl Pattern<LocationPatternKind> {
    /// 测试字符串是否匹配模式
    #[inline]
    pub fn is_match(&self, s: &str) -> bool {
        self.regex.is_match(s)
    }

    /// 获取匹配的子字符串
    #[inline]
    pub fn r#match<'s>(&self, s: &'s str) -> Option<&'s str> {
        self.regex.find(s).map(|m| &s[m.range()])
    }
}

pub fn trim_suffix_once<'s>(s: &'s str, suffix: &str) -> Option<&'s str> {
    if let Some(pos) = s.rfind(suffix)
        && pos + suffix.len() == s.len()
    {
        return Some(&s[..pos]);
    }
    None
}

impl Pattern<ClientNamePatternKind> {
    /// 测试字符串是否匹配模式
    #[inline]
    pub fn is_match(&self, s: &str) -> bool {
        trim_suffix_once(s, DhttpName::SUFFIX).is_some_and(|s| self.regex.is_match(s))
    }

    /// 获取匹配的子字符串
    #[inline]
    pub fn r#match<'s>(&self, s: &'s str) -> Option<&'s str> {
        trim_suffix_once(s, DhttpName::SUFFIX)
            .and_then(|s| self.regex.find(s).map(|m| &s[m.range()]))
    }
}

impl Pattern<DomainPatternKind> {
    /// 测试字符串是否匹配模式
    #[inline]
    pub fn is_match(&self, s: &str) -> bool {
        trim_suffix_once(s, DhttpName::SUFFIX).is_some_and(|s| self.regex.is_match(s))
    }

    /// 获取匹配的子字符串
    #[inline]
    pub fn r#match<'s>(&self, s: &'s str) -> Option<&'s str> {
        trim_suffix_once(s, DhttpName::SUFFIX)
            .and_then(|s| self.regex.find(s).map(|m| &s[m.range()]))
    }
}

macro_rules! impl_pattern {
    (impl Evaluable<&str> for Pattern<$kind:ident> { ... } $($tt:tt)*) => {
        impl Evaluable<&str> for Pattern<$kind> {
            type Value = bool;

            fn eval(&self, argument: &&str) -> Self::Value {
                self.is_match(argument)
            }
        }
        impl_pattern!($($tt)*);
    };
    (impl Pattern<$kind:ident> { pub const fn priority(&self) -> usize { ... } } $($tt:tt)*) => {
        impl Pattern<$kind> {
            /// 获取模式优先级，数值越小优先级越高
            #[inline]
            pub const fn priority(&self) -> usize {
                self.kind.priority()
            }
        }
        impl_pattern!($($tt)*);
    };
    (impl From<Pattern<$from:ident>> for Pattern<$into:ident> { ... } $($tt:tt)*) => {
        impl From<Pattern<$from>> for Pattern<$into> {
            fn from(value: Pattern<$from>) -> Self {
                Self {
                    kind: value.kind.into(),
                    regex: value.regex,
                    pattern: value.pattern,
                }
            }
        }
        impl_pattern!($($tt)*);
    };
    (impl FromStr for Pattern<$into:ident> from Pattern<$from:ident> { ... } $($tt:tt)*) => {
        impl FromStr for Pattern<$into> {
            type Err = <Pattern<$from> as FromStr>::Err;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <Pattern<$from>>::from_str(s).map(Into::into)
            }
        }
        impl_pattern!($($tt)*);
    };
    (impl Orm for Pattern<$kind:ident> from json { ... } $($tt:tt)*) => {
        const _: () = {
            type __PatternType = Pattern<$kind>;
            crate::orm_new_type!(@json __PatternType);
        };
        impl_pattern!($($tt)*);
    };
    () => {}

}

impl_pattern! {
    impl Evaluable<&str> for Pattern<NormalPatternKind> { ... }
    impl Pattern<NormalPatternKind> { pub const fn priority(&self) -> usize { ... } }
    impl Orm for Pattern<NormalPatternKind> from json { ... }

    impl Evaluable<&str> for Pattern<LocationPatternKind> { ... }
    impl Pattern<LocationPatternKind> { pub const fn priority(&self) -> usize { ... } }
    impl Orm for Pattern<LocationPatternKind> from json { ... }

    impl Evaluable<&str> for Pattern<ClientNamePatternKind> { ... }
    impl Pattern<ClientNamePatternKind> { pub const fn priority(&self) -> usize { ... } }
    impl From<Pattern<NormalPatternKind>> for Pattern<ClientNamePatternKind> { ... }
    impl FromStr for Pattern<ClientNamePatternKind> from Pattern<NormalPatternKind> { ... }
    impl Orm for Pattern<ClientNamePatternKind> from json { ... }

    impl Evaluable<&str> for Pattern<DomainPatternKind> { ... }
    impl Pattern<DomainPatternKind> { pub const fn priority(&self) -> usize { ... } }
    impl From<Pattern<NormalPatternKind>> for Pattern<DomainPatternKind> { ... }
    impl FromStr for Pattern<DomainPatternKind> from Pattern<NormalPatternKind> { ... }
    impl Orm for Pattern<DomainPatternKind> from json { ... }
}

/// 共同的正则表达式构建工具
mod regex_utils {
    use super::*;

    /// 创建不区分大小写的正则表达式
    pub(super) fn case_insensitive_regex(pat: &str) -> Result<Regex, regex::Error> {
        RegexBuilder::new(pat).case_insensitive(true).build()
    }

    /// 将 Glob 模式转换为支持非 UTF-8 字符串的正则表达式
    ///
    /// 这是处理 Glob 模式的核心函数，配置了特殊的正则表达式设置：
    /// - utf8(false): 支持非 UTF-8 字节序列匹配
    /// - dot_matches_new_line(true): 允许 . 匹配换行符
    /// - 设置了合理的内存限制防止 DoS 攻击
    pub(super) fn glob_to_regex(glob: &globset::Glob) -> Result<Regex, regex::Error> {
        glob.regex()
            .strip_prefix("(?-u)")
            .unwrap_or(glob.regex())
            .parse()
    }
}

mod parse_pattern {
    use globset::{Glob, GlobBuilder};

    use super::{regex_utils, *};

    /// 普通模式解析错误
    ///
    /// # 示例
    ///
    /// ```
    /// use dhttp_access::pattern::{NormalPattern, ParsePatternError};
    ///
    /// // 无效的正则表达式
    /// let result: Result<NormalPattern, _> = "~ [".parse();
    /// assert!(matches!(result, Err(ParsePatternError::InvalidRegex { .. })));
    ///
    /// // 注意：大多数 glob 模式实际上是有效的，这里只是示例
    /// // 实际的 InvalidGlob 错误比较难构造，通常发生在内部处理时
    /// ```
    #[derive(snafu::Snafu, Debug, Clone)]
    pub enum ParsePatternError {
        /// 无效的正则表达式
        ///
        /// # Examples
        ///
        /// ```
        /// use dhttp_access::pattern::{NormalPattern, ParsePatternError};
        ///
        /// let result: Result<NormalPattern, _> = "~ [invalid".parse();
        /// assert!(matches!(result, Err(ParsePatternError::InvalidRegex { .. })));
        ///
        /// let result: Result<NormalPattern, _> = "~* (?P<invalid".parse();
        /// assert!(matches!(result, Err(ParsePatternError::InvalidRegex { .. })));
        /// ```
        #[snafu(display("invalid regex pattern `{pattern}`"))]
        InvalidRegex {
            pattern: Arc<str>,
            source: RegexError,
        },

        /// 无效的 Glob 模式
        ///
        /// # Examples
        ///
        /// ```
        /// use dhttp_access::pattern::{NormalPattern, ParsePatternError};
        ///
        /// // 注意：实际上多数 glob 模式是有效的，这里用简化的示例
        /// let result = NormalPattern::new("***/invalid");
        /// // 由于这个例子可能不会失败，我们使用 expect 来说明预期的错误类型
        /// // assert!(matches!(result, Err(ParsePatternError::InvalidGlob { .. })));
        /// ```
        #[snafu(display("invalid glob pattern"))]
        InvalidGlob { source: globset::Error },
    }

    impl FromStr for Pattern<NormalPatternKind> {
        type Err = ParsePatternError;

        fn from_str(pattern: &str) -> Result<Self, Self::Err> {
            let pattern: Arc<str> = Arc::from(pattern);
            let (kind, regex) = match pattern.split_once(' ') {
                Some(("=", pat)) => (
                    NormalPatternKind::Exact,
                    Regex::new(&format!("^{}$", regex::escape(pat)))
                        .context(InvalidRegexSnafu { pattern: pat })?,
                ),
                Some(("*", pattern)) => {
                    let glob = GlobBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .context(InvalidGlobSnafu)?;
                    (
                        NormalPatternKind::Glob,
                        regex_utils::glob_to_regex(&glob).context(InvalidRegexSnafu { pattern })?,
                    )
                }
                Some(("~", pattern)) => (
                    NormalPatternKind::Regex,
                    Regex::new(pattern).context(InvalidRegexSnafu { pattern })?,
                ),
                Some(("~*", pattern)) => (
                    NormalPatternKind::Regex,
                    regex_utils::case_insensitive_regex(pattern)
                        .context(InvalidRegexSnafu { pattern })?,
                ),
                _ => {
                    // 对于默认的 Glob 模式
                    let glob = Glob::new(&pattern).context(InvalidGlobSnafu)?;
                    (
                        NormalPatternKind::Glob,
                        regex_utils::glob_to_regex(&glob).context(InvalidRegexSnafu {
                            pattern: pattern.clone(),
                        })?,
                    )
                }
            };
            Ok(Self {
                kind,
                regex,
                pattern,
            })
        }
    }
}

pub use parse_pattern::ParsePatternError;

mod parse_location_pattern {
    use super::{regex_utils, *};

    /// 位置模式解析错误
    ///
    /// # 示例
    ///
    /// ```
    /// use dhttp_access::pattern::{LocationPattern, ParseLocationPatternError};
    ///
    /// // 未知符号
    /// let result: Result<LocationPattern, _> = "@ /invalid".parse();
    /// assert!(matches!(result, Err(ParseLocationPatternError::UnknownSymbol { .. })));
    ///
    /// // 无效的正则表达式
    /// let result: Result<LocationPattern, _> = "~ [".parse();
    /// assert!(matches!(result, Err(ParseLocationPatternError::InvalidRegex { .. })));
    ///
    /// // 未定义的前缀或通用模式
    /// let result: Result<LocationPattern, _> = "invalid".parse();
    /// assert!(matches!(result, Err(ParseLocationPatternError::UndefinedPrefixOrCommon { .. })));
    /// ```
    #[derive(snafu::Snafu, Debug, Clone)]
    pub enum ParseLocationPatternError {
        /// 未知的符号
        ///
        /// # Examples
        ///
        /// ```
        /// use dhttp_access::pattern::{LocationPattern, ParseLocationPatternError};
        ///
        /// let result: Result<LocationPattern, _> = "@ /invalid".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::UnknownSymbol { .. })));
        ///
        /// let result: Result<LocationPattern, _> = "! /bad".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::UnknownSymbol { .. })));
        /// ```
        #[snafu(display("unknown symbol `{symbol}`, expected one of {expect:?}"))]
        UnknownSymbol {
            symbol: String,
            expect: &'static [&'static str],
        },

        /// 无效的正则表达式
        ///
        /// # Examples
        ///
        /// ```
        /// use dhttp_access::pattern::{LocationPattern, ParseLocationPatternError};
        ///
        /// let result: Result<LocationPattern, _> = "~ [invalid".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::InvalidRegex { .. })));
        ///
        /// let result: Result<LocationPattern, _> = "~* (?P<bad".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::InvalidRegex { .. })));
        /// ```
        #[snafu(display("invalid regex pattern `{pattern}`"))]
        InvalidRegex {
            pattern: Arc<str>,
            source: RegexError,
        },

        /// 未定义的前缀或通用模式
        ///
        /// # Examples
        ///
        /// ```
        /// use dhttp_access::pattern::{LocationPattern, ParseLocationPatternError};
        ///
        /// let result: Result<LocationPattern, _> = "invalid".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::UndefinedPrefixOrCommon { .. })));
        ///
        /// let result: Result<LocationPattern, _> = "not_starting_with_slash".parse();
        /// assert!(matches!(result, Err(ParseLocationPatternError::UndefinedPrefixOrCommon { .. })));
        /// ```
        #[snafu(display("expected common pattern or normal prefix starting with `{prefix}`"))]
        UndefinedPrefixOrCommon { prefix: &'static str },
    }

    impl FromStr for Pattern<LocationPatternKind> {
        type Err = ParseLocationPatternError;

        fn from_str(pattern: &str) -> Result<Self, Self::Err> {
            let pattern: Arc<str> = Arc::from(pattern);
            let (kind, regex) = match pattern.split_once(' ') {
                None if pattern.as_ref() == "/" => (
                    LocationPatternKind::Common,
                    Regex::new(r"^/").context(InvalidRegexSnafu {
                        pattern: pattern.clone(),
                    })?,
                ),
                None if pattern.starts_with("/") => (
                    LocationPatternKind::NormalPrefix,
                    Regex::new(format!("^{}", regex::escape(&pattern)).as_str()).context(
                        InvalidRegexSnafu {
                            pattern: pattern.clone(),
                        },
                    )?,
                ),
                None => return UndefinedPrefixOrCommonSnafu { prefix: "/" }.fail(),
                Some(("=", pattern)) => (
                    LocationPatternKind::Exact,
                    Regex::new(&format!("^{}$", regex::escape(pattern)))
                        .context(InvalidRegexSnafu { pattern })?,
                ),
                Some(("^~", pattern)) => (
                    LocationPatternKind::Prefix,
                    Regex::new(format!("^{}", regex::escape(pattern)).as_str())
                        .context(InvalidRegexSnafu { pattern })?,
                ),
                Some(("~", pattern)) => (
                    LocationPatternKind::Regex,
                    Regex::new(pattern).context(InvalidRegexSnafu { pattern })?,
                ),
                Some(("~*", pattern)) => (
                    LocationPatternKind::Regex,
                    regex_utils::case_insensitive_regex(pattern)
                        .context(InvalidRegexSnafu { pattern })?,
                ),
                Some((symbol, ..)) => {
                    return UnknownSymbolSnafu::fail(UnknownSymbolSnafu {
                        symbol: symbol.to_string(),
                        expect: &["=", "^~", "~", "~*"] as &'static [&'static str],
                    });
                }
            };
            Ok(Self {
                kind,
                regex,
                pattern,
            })
        }
    }
}

pub use parse_location_pattern::ParseLocationPatternError;

impl<Kind> Display for Pattern<Kind> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<Kind> Serialize for Pattern<Kind> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de, Kind> Deserialize<'de> for Pattern<Kind>
where
    Self: FromStr<Err: Display>,
{
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl<Kind: PartialEq> PartialEq for Pattern<Kind> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.pattern == other.pattern
    }
}

impl<Kind: Eq> Eq for Pattern<Kind> {}

impl<Kind: PartialOrd> PartialOrd for Pattern<Kind> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.kind
            .partial_cmp(&other.kind)
            .map(|ord| ord.then_with(|| self.pattern.cmp(&other.pattern)))
    }
}

impl<Kind: Ord> Ord for Pattern<Kind> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.pattern.cmp(&other.pattern))
    }
}

#[cfg(test)]
mod dhttp_suffix_tests {
    use super::*;

    #[test]
    fn client_name_pattern_uses_dhttp_name_suffix() {
        let pattern = Pattern::<ClientNamePatternKind>::new("~ ^reimu\\.pilot$".to_owned())
            .expect("valid client name pattern");

        assert!(pattern.is_match("reimu.pilot.dhttp.net"));
        assert!(!pattern.is_match("reimu.pilot.genmeta.net"));
    }
}
