use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};

// ============================================================================
// BytesStr — private string backed by Bytes for O(1) cloning
// ============================================================================

/// Internal string type backed by Bytes for O(1) cloning.
/// Never exposed publicly — used by [`Name::Owned`] variant.
#[derive(Clone, Debug)]
struct BytesStr(Bytes);

impl Deref for BytesStr {
    type Target = str;

    fn deref(&self) -> &str {
        // SAFETY: constructed only from valid UTF-8 (validated ASCII lowercase)
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl PartialEq for BytesStr {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for BytesStr {}

impl Hash for BytesStr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(Borrow::<str>::borrow(self), state)
    }
}

impl Borrow<str> for BytesStr {
    fn borrow(&self) -> &str {
        self.deref()
    }
}

// ============================================================================
// Validation helpers
// ============================================================================

/// Whether every byte is a non-uppercase ASCII character.
fn is_ascii_lowercase(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| !b.is_ascii_uppercase())
}

/// Owned-path constructor: validate, then lowercase in-place if needed.
fn from_bytes(bytes: Bytes) -> Result<Name<'static>, InvalidName> {
    Name::validate(&bytes)?;
    if is_ascii_lowercase(&bytes) {
        Ok(Name(Repr::Owned(BytesStr(bytes))))
    } else {
        let mut bm = BytesMut::from(bytes);
        bm.make_ascii_lowercase();
        Ok(Name(Repr::Owned(BytesStr(bm.freeze()))))
    }
}

// ============================================================================
// InvalidName — DNS name validation errors
// ============================================================================

#[derive(Debug, Snafu)]
pub enum InvalidName {
    #[snafu(display("name too long (max {} characters)", Name::MAX_LENGTH))]
    TooLong {},
    #[snafu(display("label too long (max {} characters)", Name::MAX_LABEL_LENGTH))]
    LabelTooLong {},
    #[snafu(display("name contains empty or numeric / hyphen only label"))]
    EmptyLabel {},
    #[snafu(display("name contains invalid characters"))]
    InvalidCharacter {},
    #[snafu(display("name is missing required suffix {suffix}"))]
    MissingSuffix { suffix: String },
}

// ============================================================================
// Name<'a> — DNS name, always lowercase
// ============================================================================

/// A DNS name stored as either a borrowed `&str` or an owned [`BytesStr`].
///
/// All names are normalised to ASCII lowercase. The type implements
/// [`Borrow<str>`] so that it can be used as a key in `HashMap` / `DashMap`
/// for O(1) lookups via `&str`.
#[derive(Clone, Debug)]
pub struct Name<'a>(Repr<'a>);

#[derive(Clone, Debug)]
enum Repr<'a> {
    Borrowed(&'a str),
    Owned(BytesStr),
}

impl Name<'_> {
    pub const MAX_LABEL_LENGTH: usize = 63;
    pub const MAX_LENGTH: usize = 253;

    /// Return the name as a `&str`.
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Repr::Borrowed(s) => s,
            Repr::Owned(b) => b.deref(),
        }
    }

    /// Return the complete DNS name.
    pub fn as_full(&self) -> &str {
        self.as_str()
    }

    /// Clone to an owned [`Name<'static>`].
    pub fn to_owned(&self) -> Name<'static> {
        match &self.0 {
            Repr::Borrowed(s) => Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(s.as_bytes())))),
            Repr::Owned(b) => Name(Repr::Owned(b.clone())),
        }
    }

    /// Consume and return an owned [`Name<'static>`].
    pub fn into_owned(self) -> Name<'static> {
        match self.0 {
            Repr::Borrowed(s) => Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(s.as_bytes())))),
            Repr::Owned(b) => Name(Repr::Owned(b)),
        }
    }

    /// Replace the first label with `*` to create a wildcard name.
    ///
    /// If the name is already a wildcard, returns itself as owned.
    /// If the name is a single label (no dot), returns itself unchanged.
    pub fn to_wildcard(self) -> Name<'static> {
        if self.is_wildcard() {
            return self.into_owned();
        }
        if let Some((_head, tail)) = self.as_str().split_once('.') {
            let wild = format!("*.{tail}");
            return wild.parse().expect("wildcard of valid name must be valid");
        }
        // Single label — cannot create wildcard, return as-is.
        self.into_owned()
    }

    /// Whether the first label is `*`.
    pub fn is_wildcard(&self) -> bool {
        self.as_str().starts_with('*')
    }

    /// Exact match or wildcard suffix match.
    ///
    /// If `self` is a wildcard name (e.g. `*.example.com`), matches any name
    /// whose suffix after the first label equals the wildcard's suffix.
    /// Otherwise, performs exact string comparison.
    pub fn matches(&self, name: &Name) -> bool {
        if !self.is_wildcard() {
            return self == name;
        }

        let self_tails = &self.as_str()[2..]; // skip `*.`
        name.as_str()
            .split_once('.')
            .is_some_and(|(.., tails)| tails == self_tails)
    }

    /// Validate DNS name rules without checking for any suffix.
    ///
    /// Rules enforced:
    /// - Total length ≤ 253 bytes
    /// - Each label ≤ 63 characters
    /// - No empty labels (consecutive dots, leading/trailing dot, label
    ///   starting/ending with hyphen)
    /// - No purely numeric labels
    /// - Only ASCII letters, digits, hyphens, underscores, dots, and leading `*`
    pub fn validate(input: &[u8]) -> Result<(), InvalidName> {
        enum State {
            Start,
            Next,
            NumericOnly { len: usize },
            Subsequent { len: usize },
            Hyphen { len: usize },
            Wildcard,
        }

        use State::*;

        if input.len() > Self::MAX_LENGTH {
            return Err(InvalidName::TooLong {});
        }

        let mut state = Start;
        let mut idx = 0;
        while idx < input.len() {
            let ch = input[idx];
            state = match (state, ch) {
                (Start, b'*') => Wildcard,
                (Wildcard, b'.') => Next,
                (Start | Next | Hyphen { .. }, b'.') => {
                    return Err(InvalidName::EmptyLabel {});
                }
                (Subsequent { .. }, b'.') => Next,
                (NumericOnly { .. }, b'.') => return Err(InvalidName::EmptyLabel {}),
                (Subsequent { len } | NumericOnly { len } | Hyphen { len }, _)
                    if len >= Self::MAX_LABEL_LENGTH =>
                {
                    return Err(InvalidName::LabelTooLong {});
                }
                (Start | Next, b'0'..=b'9') => NumericOnly { len: 1 },
                (NumericOnly { len }, b'0'..=b'9') => NumericOnly { len: len + 1 },
                (Start | Next, b'a'..=b'z' | b'A'..=b'Z' | b'_') => Subsequent { len: 1 },
                (Subsequent { len } | NumericOnly { len } | Hyphen { len }, b'-') => {
                    Hyphen { len: len + 1 }
                }
                (
                    Subsequent { len } | NumericOnly { len } | Hyphen { len },
                    b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9',
                ) => Subsequent { len: len + 1 },
                _ => return Err(InvalidName::InvalidCharacter {}),
            };
            idx += 1;
        }

        if matches!(state, Start | Hyphen { .. } | NumericOnly { .. }) {
            return Err(InvalidName::EmptyLabel {});
        }

        Ok(())
    }

    /// Create a [`Name<'static>`] from a `&'static str`.
    ///
    /// The static memory is wrapped in `Bytes` (no copy). If the name contains
    /// uppercase characters, it is lowercased in-place via `BytesMut`.
    pub fn from_static(s: &'static str) -> Result<Name<'static>, InvalidName> {
        from_bytes(Bytes::from_static(s.as_bytes()))
    }
}

// --- Trait implementations for Name ---

impl Deref for Name<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl Hash for Name<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(Borrow::<str>::borrow(self), state)
    }
}

impl Borrow<str> for Name<'_> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for Name<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Name<'_> {}

impl Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Name<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Name<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        Name::try_from(s).map_err(serde::de::Error::custom)
    }
}

// --- Borrowed-reference conversions (Ref path) ---

/// `TryFrom<&str>` — zero-copy `Repr::Borrowed` when already lowercase.
impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = InvalidName;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Name::validate(s.as_bytes())?;
        if is_ascii_lowercase(s.as_bytes()) {
            Ok(Name(Repr::Borrowed(s)))
        } else {
            let lower = s.to_ascii_lowercase();
            Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(
                lower.as_bytes(),
            )))))
        }
    }
}

/// `TryFrom<&[u8]>` — zero-copy `Repr::Borrowed` when already lowercase.
impl<'a> TryFrom<&'a [u8]> for Name<'a> {
    type Error = InvalidName;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Name::validate(bytes)?;
        if is_ascii_lowercase(bytes) {
            // SAFETY: Name::validate ensures only ASCII subset characters
            // (letters, digits, hyphens, underscores, dots, leading `*`),
            // all of which are valid UTF-8.
            let s = unsafe { std::str::from_utf8_unchecked(bytes) };
            Ok(Name(Repr::Borrowed(s)))
        } else {
            let lower = bytes.to_ascii_lowercase();
            Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(&lower)))))
        }
    }
}

// --- Owned conversions (always `Name<'static>`) ---

/// `FromStr` — always returns `Name<'static>`.
impl FromStr for Name<'static> {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::validate(s.as_bytes())?;
        if is_ascii_lowercase(s.as_bytes()) {
            Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(
                s.as_bytes(),
            )))))
        } else {
            let lower = s.to_ascii_lowercase();
            Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(
                lower.as_bytes(),
            )))))
        }
    }
}

impl TryFrom<String> for Name<'static> {
    type Error = InvalidName;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        from_bytes(Bytes::from(s.into_bytes()))
    }
}

impl TryFrom<Vec<u8>> for Name<'static> {
    type Error = InvalidName;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        from_bytes(Bytes::from(v))
    }
}

impl TryFrom<Bytes> for Name<'static> {
    type Error = InvalidName;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        from_bytes(bytes)
    }
}

/// `TryFrom<Cow<str>>` — always returns `Name<'static>`.
impl<'a> TryFrom<Cow<'a, str>> for Name<'static> {
    type Error = InvalidName;

    fn try_from(cow: Cow<'a, str>) -> Result<Self, Self::Error> {
        match cow {
            Cow::Borrowed(s) => {
                Name::validate(s.as_bytes())?;
                if is_ascii_lowercase(s.as_bytes()) {
                    Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(
                        s.as_bytes(),
                    )))))
                } else {
                    let lower = s.to_ascii_lowercase();
                    Ok(Name(Repr::Owned(BytesStr(Bytes::copy_from_slice(
                        lower.as_bytes(),
                    )))))
                }
            }
            Cow::Owned(s) => Name::try_from(s),
        }
    }
}

// ============================================================================
// InvalidDhttpName — DhttpName parse errors
// ============================================================================

#[derive(Debug, Snafu)]
pub enum InvalidDhttpName {
    #[snafu(transparent)]
    InvalidName { source: InvalidName },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ExpandUriError {
    #[snafu(transparent)]
    InvalidName { source: InvalidDhttpName },
    #[snafu(display("cannot expand bare dhttp shorthand without a base name"))]
    MissingBaseName,
    #[snafu(display("failed to parse expanded authority `{authority}`"))]
    ParseAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("failed to reconstruct uri with expanded dhttp name"))]
    ReconstructUri { source: http::uri::InvalidUriParts },
}

// ============================================================================
// DhttpName<'a> — Name with mandatory `.genmeta.net` suffix
// ============================================================================

/// A [`Name`] guaranteed to end with `.genmeta.net`.
///
/// Created via [`DhttpName::parse`], which handles `~` shorthand expansion
/// and appends the suffix when missing.
#[derive(Clone, Debug)]
pub struct DhttpName<'a>(Name<'a>);

impl DhttpName<'_> {
    pub const SUFFIX: &'static str = ".genmeta.net";

    /// Validate DHttp name rules, including the mandatory suffix.
    pub fn validate(input: &[u8]) -> Result<(), InvalidDhttpName> {
        if !input.ends_with(Self::SUFFIX.as_bytes()) {
            return Err(InvalidDhttpName::InvalidName {
                source: InvalidName::MissingSuffix {
                    suffix: Self::SUFFIX.to_string(),
                },
            });
        }
        match Name::validate(input) {
            Ok(()) => Ok(()),
            Err(source) => Err(InvalidDhttpName::InvalidName { source }),
        }
    }

    /// Parse and validate a [`DhttpName`].
    ///
    /// # Expansion rules
    ///
    /// 1. Input already ends with `.genmeta.net` → validate and accept as-is
    /// 2. Input ends with `~` → strip `~`, append `.genmeta.net`
    /// 3. Input contains a dot (multi-label partial) → append `.genmeta.net`
    /// 4. Otherwise → error (single label without suffix or tilde)
    ///
    /// After expansion, the resulting name is validated with
    /// [`Name::validate`].
    pub fn parse(input: &str) -> Result<DhttpName<'static>, InvalidDhttpName> {
        let processed = if input.ends_with(Self::SUFFIX) {
            input.to_owned()
        } else if let Some(partial) = input.strip_suffix('~') {
            format!("{partial}{}", Self::SUFFIX)
        } else if input.contains('.') {
            format!("{input}{}", Self::SUFFIX)
        } else {
            return Err(InvalidDhttpName::InvalidName {
                source: InvalidName::MissingSuffix {
                    suffix: Self::SUFFIX.to_string(),
                },
            });
        };

        let name = match Name::try_from(processed) {
            Ok(name) => name,
            Err(source) => return Err(InvalidDhttpName::InvalidName { source }),
        };
        Ok(DhttpName(name))
    }

    /// Parse a DHttp name, accepting either a full `.genmeta.net` name or a
    /// partial multi-label name.
    pub fn try_from_str<'a>(input: impl Into<Cow<'a, str>>) -> Result<Self, InvalidDhttpName> {
        Self::parse(input.into().as_ref())
    }

    /// Parse and validate a full DHttp name.
    pub fn try_from_str_full<'a>(input: impl Into<Cow<'a, str>>) -> Result<Self, InvalidDhttpName> {
        let input = input.into();
        if !input.ends_with(Self::SUFFIX) {
            return Err(InvalidDhttpName::InvalidName {
                source: InvalidName::MissingSuffix {
                    suffix: Self::SUFFIX.to_string(),
                },
            });
        }
        Self::parse(input.as_ref())
    }

    /// Parse a partial name by appending the DHttp suffix.
    pub fn try_from_str_partial<'a>(
        input: impl Into<Cow<'a, str>>,
    ) -> Result<Self, InvalidDhttpName> {
        let input = input.into();
        Self::parse(&format!("{}{}", input.as_ref(), Self::SUFFIX))
    }

    /// Expand only explicit DHttp forms.
    ///
    /// Returns `Some` for already-full names and `~` shorthand, and `None` for
    /// ordinary host names that should pass through unchanged.
    pub fn try_expand_from<'a>(
        input: impl Into<Cow<'a, str>>,
    ) -> Result<Option<Self>, InvalidDhttpName> {
        let input = input.into();
        if input.ends_with(Self::SUFFIX) {
            return Self::try_from_str_full(input).map(Some);
        }
        if let Some(partial) = input.strip_suffix('~') {
            return Self::try_from_str_partial(partial).map(Some);
        }

        Ok(None)
    }

    /// Consume and return the inner [`Name`].
    pub fn into_name(self) -> Name<'static> {
        self.0.into_owned()
    }

    /// Return the name without the `.genmeta.net` suffix.
    ///
    /// # Panics
    ///
    /// Panics in debug if the name does not end with the suffix (should never
    /// happen — the constructor guarantees it).
    pub fn as_partial(&self) -> &str {
        debug_assert!(self.0.as_str().ends_with(Self::SUFFIX));
        &self.0.as_str()[..self.0.as_str().len() - Self::SUFFIX.len()]
    }

    /// Return the full name including the `.genmeta.net` suffix.
    pub fn as_full(&self) -> &str {
        self.0.as_str()
    }

    /// Return a reference to the inner [`Name`].
    pub fn as_name(&self) -> &Name<'_> {
        &self.0
    }

    /// Return a borrowed DHttp name.
    pub fn borrow(&self) -> DhttpName<'_> {
        DhttpName(Name(Repr::Borrowed(self.0.as_str())))
    }

    /// Expand DHttp shorthand in the authority of `uri`.
    ///
    /// The bare host `~` expands to this name. A host ending with `~` expands
    /// to the same host with the DHttp suffix appended. Ordinary host names
    /// pass through unchanged.
    pub fn expand_uri(&self, uri: http::Uri) -> Result<http::Uri, ExpandUriError> {
        Self::expand_uri_with_base(Some(self), uri)
    }

    /// Expand DHttp shorthand in the authority of `uri` with an optional base name.
    ///
    /// The bare host `~` expands to `base` and fails when `base` is absent. A host
    /// ending with `~` expands to the same host with the DHttp suffix appended and
    /// does not require `base`. Ordinary host names pass through unchanged.
    pub fn expand_uri_with_base(
        base: Option<&DhttpName<'_>>,
        uri: http::Uri,
    ) -> Result<http::Uri, ExpandUriError> {
        let mut parts = uri.into_parts();

        let Some(authority) = &parts.authority else {
            return http::Uri::from_parts(parts).context(expand_uri_error::ReconstructUriSnafu);
        };

        let host = authority.host();
        let expanded = if host == "~" {
            Some(
                base.context(expand_uri_error::MissingBaseNameSnafu)?
                    .as_full()
                    .to_owned(),
            )
        } else {
            DhttpName::try_expand_from(host)?.map(|name| name.as_full().to_owned())
        };

        if let Some(expanded) = expanded
            && expanded.as_str() != host
        {
            let user_info_len = authority
                .as_str()
                .split_once('@')
                .map(|(user_info, ..)| user_info.len() + 1)
                .unwrap_or_default();
            let host_len = host.len();
            let authority = format!(
                "{user_info}{host}{port}",
                user_info = &authority.as_str()[..user_info_len],
                host = expanded,
                port = &authority.as_str()[user_info_len + host_len..],
            );
            parts.authority = Some(authority.parse().context(
                expand_uri_error::ParseAuthoritySnafu {
                    authority: &authority,
                },
            )?);
        }

        http::Uri::from_parts(parts).context(expand_uri_error::ReconstructUriSnafu)
    }
}

// --- Trait implementations for DhttpName ---

impl<'a> Deref for DhttpName<'a> {
    type Target = Name<'a>;

    fn deref(&self) -> &Name<'a> {
        &self.0
    }
}

/// Formats the name without the `.genmeta.net` suffix.
///
/// `Display` and [`Serialize`] both output the partial name (e.g. `reimu.pilot`),
/// while [`Deserialize`] and [`DhttpName::parse`] accept both partial and full forms.
/// Use [`DhttpName::as_full`] to obtain the complete name including the suffix.
impl Display for DhttpName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_partial())
    }
}

impl From<DhttpName<'static>> for Name<'static> {
    fn from(dn: DhttpName<'static>) -> Self {
        dn.0
    }
}

impl PartialEq for DhttpName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for DhttpName<'_> {}

impl Hash for DhttpName<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Serialize for DhttpName<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_partial())
    }
}

impl<'de> Deserialize<'de> for DhttpName<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        DhttpName::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for DhttpName<'_> {
    type Err = InvalidDhttpName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DhttpName::parse(s)
    }
}

impl TryFrom<&str> for DhttpName<'static> {
    type Error = InvalidDhttpName;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        DhttpName::parse(value)
    }
}

impl TryFrom<String> for DhttpName<'static> {
    type Error = InvalidDhttpName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DhttpName::parse(&value)
    }
}

impl<'a> TryFrom<Cow<'a, str>> for DhttpName<'static> {
    type Error = InvalidDhttpName;

    fn try_from(value: Cow<'a, str>) -> Result<Self, Self::Error> {
        DhttpName::parse(value.as_ref())
    }
}

impl DhttpName<'_> {
    /// Clone to an owned [`DhttpName<'static>`].
    pub fn to_owned(&self) -> DhttpName<'static> {
        DhttpName(self.0.to_owned())
    }

    /// Consume and return an owned [`DhttpName<'static>`].
    pub fn into_owned(self) -> DhttpName<'static> {
        DhttpName(self.0.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn name_from_static_lowercase() {
        let n = Name::from_static("example.com").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_from_static_mixed_case() {
        let n = Name::from_static("Example.COM").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_from_static_wildcard() {
        let n = Name::from_static("*.example.com").unwrap();
        assert!(n.is_wildcard());
        assert_eq!(n.as_str(), "*.example.com");
    }

    #[test]
    fn name_from_static_invalid() {
        let err = Name::from_static("!!!").unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    #[test]
    fn name_from_str_trait() {
        let n: Name = "example.com".parse().unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_from_str_trait_rejects_invalid() {
        let result: Result<Name, _> = "INVALID!!!".parse();
        assert!(result.is_err());
    }

    #[test]
    fn name_try_from_str_valid() {
        let n: Name = "example.com".parse().unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_str_too_long() {
        let long = "a".repeat(254);
        let err: Result<Name, _> = long.parse();
        assert!(matches!(err.unwrap_err(), InvalidName::TooLong {}));
    }

    #[test]
    fn name_try_from_str_empty() {
        let err: Result<Name, _> = "".parse();
        assert!(matches!(err.unwrap_err(), InvalidName::EmptyLabel {}));
    }

    #[test]
    fn name_try_from_str_invalid_char() {
        let err: Result<Name, _> = "hello!".parse();
        assert!(matches!(err.unwrap_err(), InvalidName::InvalidCharacter {}));
    }

    #[test]
    fn name_try_from_str_label_too_long() {
        let long_label = format!("{}.com", "a".repeat(64));
        let err: Result<Name, _> = long_label.parse();
        assert!(matches!(err.unwrap_err(), InvalidName::LabelTooLong {}));
    }

    #[test]
    fn name_wildcard() {
        let n: Name = "*.example.com".parse().unwrap();
        assert!(n.is_wildcard());

        let m: Name = "foo.example.com".parse().unwrap();
        assert!(n.matches(&m));
        assert!(n.matches(&n));
    }

    #[test]
    fn name_no_wildcard_match() {
        let n: Name = "a.example.com".parse().unwrap();
        let m: Name = "b.example.com".parse().unwrap();
        assert!(!n.matches(&m));
    }

    #[test]
    fn name_exact_match() {
        let n: Name = "foo.example.com".parse().unwrap();
        let m: Name = "foo.example.com".parse().unwrap();
        assert!(n.matches(&m));
    }

    #[test]
    fn name_hash_borrow_consistency() {
        use std::collections::HashSet;
        let n: Name = "example.com".parse().unwrap();
        let mut set = HashSet::new();
        set.insert(n.clone());
        assert!(set.contains("example.com"));
    }

    #[test]
    fn name_clone_owned() {
        let n: Name = "example.com".parse().unwrap();
        let c = n.clone();
        assert_eq!(n, c);
    }

    #[test]
    fn name_to_wildcard_name() {
        let n: Name = "foo.example.com".parse().unwrap();
        let w = n.to_wildcard();
        assert!(w.is_wildcard());
        assert_eq!(w.as_str(), "*.example.com");
    }

    #[test]
    fn name_wildcard_already() {
        let n: Name = "*.example.com".parse().unwrap();
        let w = n.to_wildcard();
        assert_eq!(w.as_str(), "*.example.com");
    }

    #[test]
    fn name_serialize_deserialize() {
        let n: Name = "example.com".parse().unwrap();
        let json = serde_json::to_string(&n).unwrap();
        assert_eq!(json, r#""example.com""#);
        let d: Name<'static> = serde_json::from_str(&json).unwrap();
        assert_eq!(n, d);
    }

    #[test]
    fn name_display() {
        let n: Name = "Example.COM".parse().unwrap();
        assert_eq!(format!("{n}"), "example.com");
    }

    // --- TryFrom<&str> tests ---

    #[test]
    fn name_try_from_ref_str_lowercase() {
        let n = Name::try_from("example.com").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_str_mixed_case() {
        let n = Name::try_from("Example.COM").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_str_wildcard() {
        let n = Name::try_from("*.example.com").unwrap();
        assert!(n.is_wildcard());
        assert_eq!(n.as_str(), "*.example.com");
    }

    #[test]
    fn name_try_from_ref_str_invalid() {
        let err = Name::try_from("!!!").unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    #[test]
    fn name_try_from_ref_str_borrowed_variant() {
        let input = "example.com";
        let n = Name::try_from(input).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_str_with_lifetime() {
        let owned = String::from("hello.world");
        let n = Name::try_from(owned.as_str()).unwrap();
        assert_eq!(n.as_str(), "hello.world");
    }

    // --- TryFrom<&[u8]> tests ---

    #[test]
    fn name_try_from_ref_bytes_lowercase() {
        let n = Name::try_from(b"example.com" as &[u8]).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_mixed_case() {
        let n = Name::try_from(b"Example.COM" as &[u8]).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_wildcard() {
        let n = Name::try_from(b"*.example.com" as &[u8]).unwrap();
        assert!(n.is_wildcard());
        assert_eq!(n.as_str(), "*.example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_invalid() {
        let err = Name::try_from(b"!!!" as &[u8]).unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    // --- TryFrom<String> tests ---

    #[test]
    fn name_try_from_string_mixed_case() {
        let s = String::from("Hello.World");
        let n = Name::try_from(s).unwrap();
        assert_eq!(n.as_str(), "hello.world");
    }

    #[test]
    fn name_try_from_string_invalid() {
        let s = String::from("!!!");
        let err = Name::try_from(s).unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    #[test]
    fn name_try_from_string_empty() {
        let s = String::new();
        let err = Name::try_from(s).unwrap_err();
        assert!(matches!(err, InvalidName::EmptyLabel {}));
    }

    // --- TryFrom<Vec<u8>> tests ---

    #[test]
    fn name_try_from_vec_u8_lowercase() {
        let n = Name::try_from(b"example.com".to_vec()).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_vec_u8_mixed_case() {
        let n = Name::try_from(b"Hello.World".to_vec()).unwrap();
        assert_eq!(n.as_str(), "hello.world");
    }

    #[test]
    fn name_try_from_vec_u8_invalid() {
        let err = Name::try_from(b"!!!".to_vec()).unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    // --- TryFrom<Cow<str>> tests ---

    #[test]
    fn name_try_from_cow_borrowed_lowercase() {
        let cow: Cow<'_, str> = Cow::Borrowed("example.com");
        let n = Name::try_from(cow).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_cow_borrowed_mixed_case() {
        let cow: Cow<'_, str> = Cow::Borrowed("Example.COM");
        let n = Name::try_from(cow).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_cow_owned_lowercase() {
        let cow: Cow<'_, str> = Cow::Owned("example.com".to_string());
        let n = Name::try_from(cow).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_cow_owned_mixed_case() {
        let cow: Cow<'_, str> = Cow::Owned("Example.COM".to_string());
        let n = Name::try_from(cow).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_cow_invalid() {
        let cow: Cow<'_, str> = Cow::Borrowed("!!!");
        let err = Name::try_from(cow).unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    // --- DhttpName tests ---

    #[test]
    fn dhttp_name_parse_full() {
        let dn = DhttpName::parse("hello.genmeta.net").unwrap();
        assert_eq!(dn.as_full(), "hello.genmeta.net");
        assert_eq!(dn.as_partial(), "hello");
    }

    #[test]
    fn dhttp_name_parse_partial_multi_label() {
        let dn = DhttpName::parse("reimu.pilot").unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
        assert_eq!(dn.as_partial(), "reimu.pilot");
    }

    #[test]
    fn dhttp_name_parse_partial_single_label_rejected() {
        let err = DhttpName::parse("hello").unwrap_err();
        assert!(matches!(
            err,
            InvalidDhttpName::InvalidName {
                source: InvalidName::MissingSuffix { .. }
            }
        ));
    }

    #[test]
    fn dhttp_name_serialize() {
        let dn = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let json = serde_json::to_string(&dn).unwrap();
        assert_eq!(json, "\"reimu.pilot\"");
    }

    #[test]
    fn dhttp_name_deserialize_from_partial() {
        let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot\"").unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_deserialize_from_full() {
        let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot.genmeta.net\"").unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_deserialize_rejects_invalid() {
        let result: Result<DhttpName<'static>, _> = serde_json::from_str("\"!!!\"");
        assert!(result.is_err());
    }

    #[test]
    fn dhttp_name_hash_consistent_with_name() {
        use std::hash::{DefaultHasher, Hasher};
        let dn = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let n = Name::from_static("reimu.pilot.genmeta.net").unwrap();
        let hash_dn = {
            let mut h = DefaultHasher::new();
            dn.hash(&mut h);
            h.finish()
        };
        let hash_n = {
            let mut h = DefaultHasher::new();
            n.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_dn, hash_n);
    }

    #[test]
    fn dhttp_name_eq() {
        let a = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let b = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let c = DhttpName::parse("other.pilot.genmeta.net").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn dhttp_name_to_owned_and_clone() {
        let dn = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let owned = dn.to_owned();
        assert_eq!(owned.as_full(), "reimu.pilot.genmeta.net");
        let cloned = owned.clone();
        assert_eq!(cloned.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_into_owned() {
        let dn = DhttpName::parse("reimu.pilot.genmeta.net").unwrap();
        let owned = dn.into_owned();
        assert_eq!(owned.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_from_str_trait() {
        let dn: DhttpName = "reimu.pilot.genmeta.net".parse().unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_from_str_trait_rejects_invalid() {
        let result: Result<DhttpName, _> = "!!!".parse();
        assert!(result.is_err());
    }

    #[test]
    fn dhttp_name_legacy_partial_constructor() {
        let dn = DhttpName::try_from_str_partial("reimu.pilot").unwrap();
        assert_eq!(dn.as_partial(), "reimu.pilot");
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_legacy_full_constructor() {
        let dn = DhttpName::try_from_str_full("reimu.pilot.genmeta.net").unwrap();
        assert_eq!(dn.as_partial(), "reimu.pilot");
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_legacy_expand_constructor() {
        let dn = DhttpName::try_expand_from("reimu.pilot~")
            .unwrap()
            .expect("tilde shorthand should expand");
        assert_eq!(dn.as_full(), "reimu.pilot.genmeta.net");

        let none = DhttpName::try_expand_from("example.com").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn dhttp_name_legacy_borrow_method() {
        let dn = DhttpName::parse("reimu.pilot").unwrap();
        let borrowed = dn.borrow();
        assert_eq!(borrowed.as_full(), dn.as_full());
    }

    #[test]
    fn dhttp_name_legacy_validate() {
        DhttpName::validate(b"reimu.pilot.genmeta.net").unwrap();
        assert!(DhttpName::validate(b"reimu.pilot").is_err());
    }

    #[test]
    fn dhttp_name_try_from_str_expands_partial_name() {
        let name = DhttpName::try_from("reimu.pilot").unwrap();
        assert_eq!(name.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn dhttp_name_try_from_string_expands_tilde_name() {
        let name = DhttpName::try_from(String::from("reimu.pilot~")).unwrap();
        assert_eq!(name.as_full(), "reimu.pilot.genmeta.net");
    }

    #[test]
    fn expand_uri_replaces_bare_tilde_with_self_name() {
        let name = DhttpName::parse("reimu.pilot").unwrap();
        let uri = "https://~/api?q=1".parse().unwrap();

        let expanded = name.expand_uri(uri).unwrap();

        assert_eq!(
            expanded.to_string(),
            "https://reimu.pilot.genmeta.net/api?q=1"
        );
    }

    #[test]
    fn expand_uri_expands_tilde_suffix_and_preserves_userinfo_port() {
        let name = DhttpName::parse("self.host").unwrap();
        let uri = "https://alice@reimu.pilot~:443/api".parse().unwrap();

        let expanded = name.expand_uri(uri).unwrap();

        assert_eq!(
            expanded.to_string(),
            "https://alice@reimu.pilot.genmeta.net:443/api"
        );
    }

    #[test]
    fn expand_uri_leaves_plain_host_unchanged() {
        let name = DhttpName::parse("self.host").unwrap();
        let uri: http::Uri = "https://example.com/api".parse().unwrap();

        let expanded = name.expand_uri(uri.clone()).unwrap();

        assert_eq!(expanded, uri);
    }

    #[test]
    fn expand_uri_rejects_invalid_expanded_name() {
        let name = DhttpName::parse("self.host").unwrap();
        let uri = "https://123~/api".parse().unwrap();

        let error = name.expand_uri(uri).unwrap_err();

        assert!(matches!(error, ExpandUriError::InvalidName { .. }));
    }

    #[test]
    fn expand_uri_with_base_expands_partial_without_base_name() {
        let uri = "https://reimu.pilot~/api".parse().unwrap();

        let expanded = DhttpName::expand_uri_with_base(None, uri).unwrap();

        assert_eq!(expanded.to_string(), "https://reimu.pilot.genmeta.net/api");
    }

    #[test]
    fn expand_uri_with_base_requires_base_name_for_bare_tilde() {
        let uri = "https://~/api".parse().unwrap();

        let error = DhttpName::expand_uri_with_base(None, uri).unwrap_err();

        assert!(matches!(error, ExpandUriError::MissingBaseName));
    }
}
