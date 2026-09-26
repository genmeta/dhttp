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
    input.replace('~', DhttpName::SUFFIX)
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
