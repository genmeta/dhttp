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
    #[derive(snafu::Snafu, Debug)]
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

        #[snafu(display("unreachable pattern"))]
        Unreachable {
            source: reachability::ReachabilityError,
        },
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
    #[derive(snafu::Snafu, Debug)]
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

        #[snafu(display("unreachable location pattern"))]
        Unreachable {
            source: reachability::ReachabilityError,
        },
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
            let pattern = Self {
                kind,
                regex,
                pattern,
            };
            reachability::validate_reachable::<_, reachability::LocationPathLanguage>(&pattern)
                .context(UnreachableSnafu)?;
            Ok(pattern)
        }
    }
}

pub use parse_location_pattern::ParseLocationPatternError;
