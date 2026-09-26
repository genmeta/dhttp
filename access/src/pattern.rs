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

pub mod reachability;

include!("pattern/matching.rs");
include!("pattern/parsing.rs");
include!("pattern/traits.rs");

#[cfg(test)]
#[path = "../tests/unit/pattern.rs"]
mod dhttp_suffix_tests;
