use std::{fmt::Display, str::FromStr, sync::Arc};

use derive_more::{AsRef, From, Into};
use dhttp_home::DHTTP_SUFFIX;
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

pub mod reachability;

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

impl Pattern<ClientNamePatternKind> {
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

impl Pattern<DomainPatternKind> {
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
    impl Orm for Pattern<ClientNamePatternKind> from json { ... }

    impl Evaluable<&str> for Pattern<DomainPatternKind> { ... }
    impl Pattern<DomainPatternKind> { pub const fn priority(&self) -> usize { ... } }
    impl From<Pattern<NormalPatternKind>> for Pattern<DomainPatternKind> { ... }
    impl Orm for Pattern<DomainPatternKind> from json { ... }
}

fn expand_name_glob_or_exact(input: &str) -> String {
    input.replace('~', DHTTP_SUFFIX)
}

fn expand_name_regex(input: &str) -> String {
    input.replace('~', r"\.dhttp\.net")
}

fn canonicalize_name_pattern(pattern: &str) -> String {
    match pattern.split_once(' ') {
        Some(("~", regex)) => format!("~ {}", expand_name_regex(regex)),
        Some(("~*", regex)) => format!("~* {}", expand_name_regex(regex)),
        Some(("=", exact)) => format!("= {}", expand_name_glob_or_exact(exact)),
        Some(("*", glob)) => format!("* {}", expand_name_glob_or_exact(glob)),
        _ => expand_name_glob_or_exact(pattern),
    }
}

impl FromStr for Pattern<ClientNamePatternKind> {
    type Err = ParsePatternError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let canonical = canonicalize_name_pattern(s);
        let pattern: Self = <Pattern<NormalPatternKind>>::from_str(&canonical).map(Into::into)?;
        reachability::validate_reachable::<_, reachability::ClientNameLanguage>(&pattern)
            .map_err(|source| ParsePatternError::Unreachable { source })?;
        Ok(pattern)
    }
}

impl FromStr for Pattern<DomainPatternKind> {
    type Err = ParsePatternError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let canonical = canonicalize_name_pattern(s);
        let pattern: Self = <Pattern<NormalPatternKind>>::from_str(&canonical).map(Into::into)?;
        reachability::validate_reachable::<_, reachability::DomainNameLanguage>(&pattern)
            .map_err(|source| ParsePatternError::Unreachable { source })?;
        Ok(pattern)
    }
}

mod parsing;
pub use parsing::{ParseLocationPatternError, ParsePatternError};
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
#[path = "../tests/unit/pattern.rs"]
mod dhttp_suffix_tests;
