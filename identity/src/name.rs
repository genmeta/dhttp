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

// Keep the existing private types and conversions in this module.
// ============================================================================
// BytesStr — private string backed by Bytes for O(1) cloning
// ============================================================================

/// Internal string type backed by Bytes for O(1) cloning.
/// Never exposed publicly — used by [`Name::Owned`] variant.
#[derive(Clone, Debug)]
struct BytesStr(Bytes);

impl Deref for BytesStr {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        // SAFETY: constructed only from valid UTF-8 (validated ASCII lowercase)
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl PartialEq for BytesStr {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for BytesStr {}

impl Hash for BytesStr {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(Borrow::<str>::borrow(self), state)
    }
}

impl Borrow<str> for BytesStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.deref()
    }
}

impl AsRef<str> for BytesStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.deref()
    }
}

impl BytesStr {
    #[inline]
    fn modify(&mut self, modify: impl FnOnce(&mut String)) {
        let mut string = self.as_ref().to_owned();
        modify(&mut string);
        self.0 = Bytes::from(string.into_bytes());
    }
}

#[derive(Clone, Debug)]
pub enum CowBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Bytes),
}

impl<'a> From<&'a str> for CowBytes<'a> {
    #[inline]
    fn from(value: &'a str) -> Self {
        Self::Borrowed(value.as_bytes())
    }
}

impl<'a> From<&'a [u8]> for CowBytes<'a> {
    #[inline]
    fn from(value: &'a [u8]) -> Self {
        Self::Borrowed(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for CowBytes<'a> {
    #[inline]
    fn from(value: &'a [u8; N]) -> Self {
        Self::Borrowed(&value[..])
    }
}

impl From<String> for CowBytes<'static> {
    #[inline]
    fn from(value: String) -> Self {
        Self::Owned(Bytes::from(value.into_bytes()))
    }
}

impl From<Vec<u8>> for CowBytes<'static> {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self::Owned(Bytes::from(value))
    }
}

impl From<Bytes> for CowBytes<'static> {
    #[inline]
    fn from(value: Bytes) -> Self {
        Self::Owned(value)
    }
}

impl<'a> From<Cow<'a, str>> for CowBytes<'a> {
    #[inline]
    fn from(value: Cow<'a, str>) -> Self {
        match value {
            Cow::Borrowed(value) => Self::Borrowed(value.as_bytes()),
            Cow::Owned(value) => Self::Owned(Bytes::from(value.into_bytes())),
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for CowBytes<'a> {
    #[inline]
    fn from(value: Cow<'a, [u8]>) -> Self {
        match value {
            Cow::Borrowed(value) => Self::Borrowed(value),
            Cow::Owned(value) => Self::Owned(Bytes::from(value)),
        }
    }
}

impl AsRef<[u8]> for CowBytes<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

fn expand_dhttp_shorthand<'a>(input: CowBytes<'a>) -> CowBytes<'a> {
    let bytes = input.as_ref();
    if !bytes.contains(&b'~') {
        return input;
    }

    let suffix = DhttpName::SUFFIX.as_bytes();
    let extra = bytes.iter().filter(|byte| **byte == b'~').count() * (suffix.len() - 1);
    let mut expanded = BytesMut::with_capacity(bytes.len() + extra);
    for byte in bytes {
        if *byte == b'~' {
            expanded.extend_from_slice(suffix);
        } else {
            expanded.extend_from_slice(&[*byte]);
        }
    }
    CowBytes::Owned(expanded.freeze())
}

#[derive(Clone, Debug)]
enum CowBytesStr<'a> {
    Borrowed(&'a str),
    Owned(BytesStr),
}

impl CowBytesStr<'_> {
    #[inline]
    fn modify(&mut self, modify: impl FnOnce(&mut String)) {
        match self {
            Self::Borrowed(value) => {
                let mut owned = BytesStr(Bytes::from(value.to_owned()));
                owned.modify(modify);
                *self = Self::Owned(owned);
            }
            Self::Owned(value) => value.modify(modify),
        }
    }

    #[inline]
    fn into_owned(self) -> CowBytesStr<'static> {
        match self {
            Self::Borrowed(value) => CowBytesStr::Owned(BytesStr(Bytes::from(value.to_owned()))),
            Self::Owned(value) => CowBytesStr::Owned(value),
        }
    }

    #[inline]
    fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(value) => Bytes::from(value.to_owned()),
            Self::Owned(value) => value.0,
        }
    }
}

impl AsRef<str> for CowBytesStr<'_> {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value.as_ref(),
        }
    }
}

#[derive(Clone, Debug)]
struct DnsName<S>(S);

impl<S: AsRef<str>> AsRef<str> for DnsName<S> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<S: AsRef<[u8]>> DnsName<S> {
    const MAX_LABEL_LENGTH: usize = 63;
    const MAX_LENGTH: usize = 253;

    /// Validate DNS name rules without checking for any suffix.
    ///
    /// Rules enforced:
    /// - Total length ≤ 253 bytes
    /// - Each label ≤ 63 characters
    /// - No empty labels (consecutive dots, leading/trailing dot, label
    ///   starting/ending with hyphen)
    /// - No purely numeric labels
    /// - Only ASCII letters, digits, hyphens, underscores, dots, and leading `*`
    fn validate(input: S) -> Result<S, InvalidName> {
        enum State {
            Start,
            Next,
            NumericOnly { len: usize },
            Subsequent { len: usize },
            Hyphen { len: usize },
            Wildcard,
        }

        use State::*;

        let bytes = input.as_ref();

        if bytes.len() > Self::MAX_LENGTH {
            return Err(InvalidName::TooLong {});
        }

        let mut state = Start;
        let mut idx = 0;
        while idx < bytes.len() {
            let ch = bytes[idx];
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

        Ok(input)
    }
}

impl<'a> TryFrom<CowBytes<'a>> for DnsName<CowBytesStr<'a>> {
    type Error = InvalidName;

    #[inline]
    fn try_from(value: CowBytes<'a>) -> Result<Self, Self::Error> {
        let value = DnsName::<CowBytes>::validate(value)?;
        Ok(DnsName(match value {
            CowBytes::Borrowed(bytes) => {
                // SAFETY: DnsName::validate accepts only ASCII DNS-name bytes,
                // which are valid UTF-8.
                CowBytesStr::Borrowed(unsafe { std::str::from_utf8_unchecked(bytes) })
            }
            CowBytes::Owned(bytes) => CowBytesStr::Owned(BytesStr(bytes)),
        }))
    }
}

impl<'a> DnsName<CowBytesStr<'a>> {
    #[inline]
    fn try_from_static(value: &'static [u8]) -> Result<Self, InvalidName> {
        DnsName::try_from(CowBytes::Owned(Bytes::from_static(value)))
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

/// A DNS name stored as either a borrowed `&str` or an owned byte-backed string.
///
/// All names are normalised to ASCII lowercase. The type implements
/// [`Borrow<str>`] so that it can be used as a key in `HashMap` / `DashMap`
/// for O(1) lookups via `&str`.
#[derive(Clone, Debug)]
pub struct Name<'a>(DnsName<CowBytesStr<'a>>);

impl Name<'_> {
    pub const MAX_LABEL_LENGTH: usize = DnsName::<CowBytes<'static>>::MAX_LABEL_LENGTH;
    pub const MAX_LENGTH: usize = DnsName::<CowBytes<'static>>::MAX_LENGTH;

    /// Parse a DNS name while treating each `~` byte as shorthand for
    /// [`DhttpName::SUFFIX`].
    ///
    /// Unlike [`DhttpName::try_from`], this does not implicitly append the
    /// DHTTP suffix when `~` is absent.
    #[inline]
    pub fn from_dhttp_shorthand<'a>(
        input: impl Into<CowBytes<'a>>,
    ) -> Result<Name<'a>, InvalidName> {
        let input = expand_dhttp_shorthand(input.into());
        DnsName::try_from(input).map(Name::from)
    }

    /// Return the name as a `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Return the complete DNS name.
    #[inline]
    pub fn as_full(&self) -> &str {
        self.as_str()
    }

    /// Clone to an owned [`Name<'static>`].
    #[inline]
    pub fn to_owned(&self) -> Name<'static> {
        Name(DnsName(self.0.0.clone().into_owned()))
    }

    /// Consume and return an owned [`Name<'static>`].
    #[inline]
    pub fn into_owned(self) -> Name<'static> {
        Name(DnsName(self.0.0.into_owned()))
    }

    /// Consume and return this name as bytes.
    ///
    /// Owned names reuse the existing [`Bytes`] allocation. Borrowed names are
    /// copied because the returned bytes must own their storage.
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.0.0.into_bytes()
    }

    /// Replace the first label with `*` to create a wildcard name.
    ///
    /// If the name is already a wildcard, returns itself as owned.
    /// If the name is a single label (no dot), returns itself unchanged.
    #[inline]
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
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.as_str().starts_with('*')
    }

    /// Exact match or wildcard suffix match.
    ///
    /// If `self` is a wildcard name (e.g. `*.example.com`), matches any name
    /// whose suffix after the first label equals the wildcard's suffix.
    /// Otherwise, performs exact string comparison.
    #[inline]
    pub fn matches(&self, name: &Name) -> bool {
        if !self.is_wildcard() {
            return self == name;
        }

        let self_tails = &self.as_str()[2..]; // skip `*.`
        name.as_str()
            .split_once('.')
            .is_some_and(|(.., tails)| tails == self_tails)
    }

    #[inline]
    pub fn try_from_static(bytes: &'static [u8]) -> Result<Name<'static>, InvalidName> {
        Ok(Name::from(
            DnsName::<CowBytesStr<'static>>::try_from_static(bytes)?,
        ))
    }
}

// --- Trait implementations for Name ---

impl Deref for Name<'_> {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl Hash for Name<'_> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(Borrow::<str>::borrow(self), state)
    }
}

impl Borrow<str> for Name<'_> {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for Name<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Name<'_> {}

impl Display for Name<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Name<'_> {
    #[inline]
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

impl<'a> From<DnsName<CowBytesStr<'a>>> for Name<'a> {
    #[inline]
    fn from(mut value: DnsName<CowBytesStr<'a>>) -> Self {
        if value.as_ref().bytes().any(|byte| byte.is_ascii_uppercase()) {
            value.0.modify(|string| string.make_ascii_lowercase());
        }
        Name(value)
    }
}

// --- Borrowed-reference conversions (Ref path) ---

/// `TryFrom<&str>` — zero-copy when the validated name is already lowercase.
impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = InvalidName;

    #[inline]
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Name::try_from(s.as_bytes())
    }
}

/// `TryFrom<&[u8]>` — zero-copy when the validated name is already lowercase.
impl<'a> TryFrom<&'a [u8]> for Name<'a> {
    type Error = InvalidName;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        DnsName::try_from(CowBytes::Borrowed(bytes)).map(Name::from)
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for Name<'a> {
    type Error = InvalidName;

    #[inline]
    fn try_from(bytes: &'a [u8; N]) -> Result<Self, Self::Error> {
        Name::try_from(&bytes[..])
    }
}

// --- Owned conversions (always `Name<'static>`) ---

/// `FromStr` — always returns `Name<'static>`.
impl FromStr for Name<'static> {
    type Err = InvalidName;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::try_from(s).map(Name::into_owned)
    }
}

impl TryFrom<String> for Name<'_> {
    type Error = InvalidName;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Name::try_from(s.into_bytes())
    }
}

impl TryFrom<Vec<u8>> for Name<'_> {
    type Error = InvalidName;

    #[inline]
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Name::try_from(Bytes::from(v))
    }
}

impl TryFrom<Bytes> for Name<'_> {
    type Error = InvalidName;

    #[inline]
    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        DnsName::try_from(CowBytes::Owned(bytes)).map(Name::from)
    }
}

/// `TryFrom<Cow<str>>` — borrows borrowed input when possible and reuses owned
/// input storage.
impl<'a> TryFrom<Cow<'a, str>> for Name<'a> {
    type Error = InvalidName;

    #[inline]
    fn try_from(cow: Cow<'a, str>) -> Result<Self, Self::Error> {
        match cow {
            Cow::Borrowed(s) => Name::try_from(s),
            Cow::Owned(s) => Name::try_from(s),
        }
    }
}

impl<'a> TryFrom<Cow<'a, [u8]>> for Name<'a> {
    type Error = InvalidName;

    #[inline]
    fn try_from(cow: Cow<'a, [u8]>) -> Result<Self, Self::Error> {
        match cow {
            Cow::Borrowed(bytes) => Name::try_from(bytes),
            Cow::Owned(bytes) => Name::try_from(bytes),
        }
    }
}

mod dhttp_name;
pub use dhttp_name::{DhttpName, ExpandAuthorityError, ExpandUriError, InvalidDhttpName};

#[cfg(test)]
#[path = "../tests/unit/name.rs"]
mod tests;
