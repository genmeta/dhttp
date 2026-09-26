/// 键值对模式，用于匹配HTTP头或查询参数
///
/// TODO: 支持key的匹配项参与匹配?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KVPattern {
    pub key: NormalPattern,
    pub value: NormalPattern,
}

impl KVPattern {
    pub fn new<K, V, KL, VL>(key: K, value: V) -> Result<Self, BuildAtomicPatternError>
    where
        K: Into<NormalPattern>,
        V: Into<NormalPattern>,
        KL: PatternInputLanguage,
        VL: PatternInputLanguage,
    {
        let key = key.into();
        let value = value.into();
        validate_reachable::<_, KL>(&key).map_err(|source| {
            BuildAtomicPatternError::Unreachable {
                domain: KL::label(),
                source,
            }
        })?;
        validate_reachable::<_, VL>(&value).map_err(|source| {
            BuildAtomicPatternError::Unreachable {
                domain: VL::label(),
                source,
            }
        })?;
        Ok(Self { key, value })
    }

    pub fn new_header(
        key: NormalPattern,
        value: NormalPattern,
    ) -> Result<Self, BuildAtomicPatternError> {
        Self::new::<_, _, HeaderNameLanguage, HeaderValueLanguage>(key, value)
    }

    pub fn new_query(
        key: NormalPattern,
        value: NormalPattern,
    ) -> Result<Self, BuildAtomicPatternError> {
        Self::new::<_, _, QueryKeyLanguage, QueryValueLanguage>(key, value)
    }
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

#[derive(Debug, Clone, Into, AsRef, PartialEq, Eq)]
pub struct Header {
    pattern: KVPattern,
}

impl Header {
    pub fn new(pattern: KVPattern) -> Self {
        Self { pattern }
    }
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

#[derive(Debug, Clone, Into, AsRef, PartialEq, Eq)]
pub struct Query {
    pattern: KVPattern,
}

impl Query {
    pub fn new(pattern: KVPattern) -> Self {
        Self { pattern }
    }
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
