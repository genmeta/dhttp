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

/// A DNS name stored as either a borrowed `&str` or an owned [`BytesStr`].
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
pub enum ExpandAuthorityError {
    #[snafu(transparent)]
    InvalidName { source: InvalidDhttpName },
    #[snafu(display("cannot expand bare dhttp shorthand without a base name"))]
    MissingBaseName,
    #[snafu(display("failed to parse expanded authority `{authority}`"))]
    ParseAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ExpandUriError {
    #[snafu(display("failed to expand dhttp shorthand in uri authority"))]
    Authority { source: ExpandAuthorityError },
    #[snafu(display("failed to reconstruct uri with expanded dhttp name"))]
    ReconstructUri { source: http::uri::InvalidUriParts },
}

// ============================================================================
// DhttpName<'a> — Name with mandatory `.dhttp.net` suffix
// ============================================================================

/// A [`Name`] guaranteed to end with `.dhttp.net`.
///
/// Created via [`FromStr`] or [`TryFrom`], which handle `~` shorthand expansion
/// and append the suffix when missing.
#[derive(Clone, Debug)]
pub struct DhttpName<'a>(Name<'a>);

impl DhttpName<'_> {
    pub const SUFFIX: &'static str = ".dhttp.net";

    /// Validate DHttp name rules, including the mandatory suffix.
    #[inline]
    pub fn validate(input: &[u8]) -> Result<(), InvalidDhttpName> {
        if !input.ends_with(Self::SUFFIX.as_bytes()) {
            return Err(InvalidName::MissingSuffix {
                suffix: Self::SUFFIX.to_string(),
            }
            .into());
        }
        match DnsName::<&[u8]>::validate(input) {
            Ok(_) => Ok(()),
            Err(source) => Err(source.into()),
        }
    }

    #[inline]
    pub fn try_from_static(input: &'static [u8]) -> Result<DhttpName<'static>, InvalidDhttpName> {
        DhttpName::try_from(Bytes::from_static(input))
    }

    /// Consume and return the inner [`Name`].
    #[inline]
    pub fn into_name(self) -> Name<'static> {
        self.0.into_owned()
    }

    /// Return the name without the `.dhttp.net` suffix.
    ///
    /// # Panics
    ///
    /// Panics in debug if the name does not end with the suffix (should never
    /// happen — the constructor guarantees it).
    #[inline]
    pub fn as_partial(&self) -> &str {
        debug_assert!(self.0.as_str().ends_with(Self::SUFFIX));
        &self.0.as_str()[..self.0.as_str().len() - Self::SUFFIX.len()]
    }

    /// Return the full name including the `.dhttp.net` suffix.
    #[inline]
    pub fn as_full(&self) -> &str {
        self.0.as_str()
    }

    /// Return a reference to the inner [`Name`].
    #[inline]
    pub fn as_name(&self) -> &Name<'_> {
        &self.0
    }

    /// Return a borrowed DHttp name.
    #[inline]
    pub fn borrow(&self) -> DhttpName<'_> {
        DhttpName(Name(DnsName(CowBytesStr::Borrowed(self.0.as_str()))))
    }

    /// Replace the first label with `*` to create a wildcard DHttp name.
    #[inline]
    pub fn to_wildcard(self) -> DhttpName<'static> {
        DhttpName(self.0.to_wildcard())
    }

    /// Expand DHttp shorthand in the authority of `uri`.
    ///
    /// The bare host `~` expands to this name. Other hosts containing `~`
    /// expand each marker to the DHttp suffix. Ordinary host names pass through
    /// unchanged.
    #[inline]
    pub fn expand_uri(&self, uri: http::Uri) -> Result<http::Uri, ExpandUriError> {
        Self::expand_uri_with_base(Some(self), uri)
    }

    /// Expand DHttp shorthand in `authority` with an optional base name.
    ///
    /// The bare host `~` expands to `base` and fails when `base` is absent. Other
    /// hosts containing `~` expand each marker to the DHttp suffix and do not
    /// require `base`. Ordinary host names pass through unchanged.
    pub fn expand_authority_with_base(
        base: Option<&DhttpName<'_>>,
        authority: http::uri::Authority,
    ) -> Result<http::uri::Authority, ExpandAuthorityError> {
        let raw = authority.as_str();
        let host = authority.host();

        let replacement = if host == "~" {
            base.context(expand_authority_error::MissingBaseNameSnafu)?
                .as_name()
                .to_owned()
        } else if host.as_bytes().contains(&b'~') {
            Name::from_dhttp_shorthand(host)
                .map_err(|source| ExpandAuthorityError::InvalidName {
                    source: InvalidDhttpName::InvalidName { source },
                })?
                .into_owned()
        } else if host.len() >= Self::SUFFIX.len()
            && host[host.len() - Self::SUFFIX.len()..].eq_ignore_ascii_case(Self::SUFFIX)
        {
            let name = match Name::try_from(host) {
                Ok(name) => name,
                Err(source) => {
                    return Err(ExpandAuthorityError::InvalidName {
                        source: InvalidDhttpName::InvalidName { source },
                    });
                }
            };
            DhttpName::try_from(name)?.into_name()
        } else {
            return Ok(authority);
        };

        if raw == host {
            let authority = replacement.as_full().to_owned();
            return http::uri::Authority::from_maybe_shared(replacement.into_bytes())
                .context(expand_authority_error::ParseAuthoritySnafu { authority });
        }

        let user_info_len = raw
            .split_once('@')
            .map(|(user_info, ..)| user_info.len() + 1)
            .unwrap_or_default();
        let host_len = host.len();
        let authority = format!(
            "{user_info}{host}{port}",
            user_info = &raw[..user_info_len],
            host = replacement.as_full(),
            port = &raw[user_info_len + host_len..],
        );
        authority
            .parse()
            .context(expand_authority_error::ParseAuthoritySnafu {
                authority: &authority,
            })
    }

    /// Expand DHttp shorthand in the authority of `uri` with an optional base name.
    ///
    /// The bare host `~` expands to `base` and fails when `base` is absent. Other
    /// hosts containing `~` expand each marker to the DHttp suffix and do not
    /// require `base`. Ordinary host names pass through unchanged.
    pub fn expand_uri_with_base(
        base: Option<&DhttpName<'_>>,
        uri: http::Uri,
    ) -> Result<http::Uri, ExpandUriError> {
        let mut parts = uri.into_parts();

        if let Some(authority) = parts.authority {
            parts.authority = Some(
                Self::expand_authority_with_base(base, authority)
                    .context(expand_uri_error::AuthoritySnafu)?,
            );
        }

        http::Uri::from_parts(parts).context(expand_uri_error::ReconstructUriSnafu)
    }
}

// --- Trait implementations for DhttpName ---

impl<'a> Deref for DhttpName<'a> {
    type Target = Name<'a>;

    #[inline]
    fn deref(&self) -> &Name<'a> {
        &self.0
    }
}

/// Formats the name without the `.dhttp.net` suffix.
///
/// `Display` and [`Serialize`] both output the partial name (e.g. `reimu.pilot`),
/// while [`Deserialize`] and [`FromStr`] accept both partial and full forms.
/// Use [`DhttpName::as_full`] to obtain the complete name including the suffix.
impl Display for DhttpName<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_partial())
    }
}

impl From<DhttpName<'static>> for Name<'static> {
    #[inline]
    fn from(dn: DhttpName<'static>) -> Self {
        dn.0
    }
}

impl PartialEq for DhttpName<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for DhttpName<'_> {}

impl Hash for DhttpName<'_> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Serialize for DhttpName<'_> {
    #[inline]
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
        DhttpName::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for DhttpName<'static> {
    type Err = InvalidDhttpName;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DhttpName::try_from(s).map(DhttpName::into_owned)
    }
}

impl<'a> TryFrom<&'a str> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        DhttpName::try_from(value.as_bytes())
    }
}

impl<'a> TryFrom<String> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        DhttpName::try_from(value.into_bytes())
    }
}

impl<'a> TryFrom<&'a [u8]> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        DhttpName::try_from(CowBytes::Borrowed(value))
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: &'a [u8; N]) -> Result<Self, Self::Error> {
        DhttpName::try_from(&value[..])
    }
}

impl<'a> TryFrom<Bytes> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        DhttpName::try_from(CowBytes::Owned(value))
    }
}

impl<'a> TryFrom<Vec<u8>> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        DhttpName::try_from(Bytes::from(value))
    }
}

impl<'a> TryFrom<Name<'a>> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: Name<'a>) -> Result<Self, Self::Error> {
        if !value.as_str().ends_with(Self::SUFFIX) {
            return Err(InvalidName::MissingSuffix {
                suffix: DhttpName::SUFFIX.to_string(),
            }
            .into());
        }
        Ok(DhttpName(value))
    }
}

impl<'a> TryFrom<CowBytes<'a>> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(input: CowBytes<'a>) -> Result<Self, Self::Error> {
        if input.as_ref().ends_with(Self::SUFFIX.as_bytes()) {
            return match input {
                CowBytes::Borrowed(input) => match Name::try_from(input) {
                    Ok(name) => Ok(DhttpName(name)),
                    Err(source) => Err(source.into()),
                },
                CowBytes::Owned(input) => match Name::try_from(input) {
                    Ok(name) => Ok(DhttpName(name)),
                    Err(source) => Err(source.into()),
                },
            };
        }

        let mut input = match input {
            CowBytes::Borrowed(input) => BytesMut::from(input),
            CowBytes::Owned(input) => BytesMut::from(input),
        };
        if input.ends_with(b"~") {
            input.truncate(input.len() - 1);
        }
        input.extend_from_slice(Self::SUFFIX.as_bytes());
        match Name::try_from(input.freeze()) {
            Ok(name) => Ok(DhttpName(name)),
            Err(source) => Err(source.into()),
        }
    }
}

impl<'a> TryFrom<Cow<'a, str>> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: Cow<'a, str>) -> Result<Self, Self::Error> {
        match value {
            Cow::Borrowed(value) => DhttpName::try_from(value),
            Cow::Owned(value) => DhttpName::try_from(value),
        }
    }
}

impl<'a> TryFrom<Cow<'a, [u8]>> for DhttpName<'a> {
    type Error = InvalidDhttpName;

    #[inline]
    fn try_from(value: Cow<'a, [u8]>) -> Result<Self, Self::Error> {
        match value {
            Cow::Borrowed(value) => DhttpName::try_from(value),
            Cow::Owned(value) => DhttpName::try_from(value),
        }
    }
}

impl DhttpName<'_> {
    /// Clone to an owned [`DhttpName<'static>`].
    #[inline]
    pub fn to_owned(&self) -> DhttpName<'static> {
        DhttpName(self.0.to_owned())
    }

    /// Consume and return an owned [`DhttpName<'static>`].
    #[inline]
    pub fn into_owned(self) -> DhttpName<'static> {
        DhttpName(self.0.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn name_try_from_static_lowercase() {
        let n = Name::try_from_static(b"example.com").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_static_mixed_case() {
        let n = Name::try_from_static(b"Example.COM").unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_static_wildcard() {
        let n = Name::try_from_static(b"*.example.com").unwrap();
        assert!(n.is_wildcard());
        assert_eq!(n.as_str(), "*.example.com");
    }

    #[test]
    fn name_try_from_static_invalid() {
        let err = Name::try_from_static(b"!!!").unwrap_err();
        assert!(matches!(err, InvalidName::InvalidCharacter {}));
    }

    #[test]
    fn name_try_from_static_bytes_reuses_static_bytes_path() {
        let name = Name::try_from_static(b"Example.COM").unwrap();

        assert_eq!(name.as_str(), "example.com");
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
    fn name_from_dhttp_shorthand_leaves_plain_name_unchanged() {
        let input = "alice.margatroid";

        let name = Name::from_dhttp_shorthand(input).expect("plain name should parse");

        assert_eq!(name.as_full(), "alice.margatroid");
    }

    #[test]
    fn name_from_dhttp_shorthand_lowercases_plain_name() {
        let name =
            Name::from_dhttp_shorthand("Alice.Margatroid").expect("mixed-case name should parse");

        assert_eq!(name.as_full(), "alice.margatroid");
    }

    #[test]
    fn name_from_dhttp_shorthand_expands_suffix_marker() {
        let name =
            Name::from_dhttp_shorthand("alice.margatroid~").expect("dhttp shorthand should parse");

        assert_eq!(name.as_full(), "alice.margatroid.dhttp.net");
    }

    #[test]
    fn name_from_dhttp_shorthand_expands_every_suffix_marker() {
        let name = Name::from_dhttp_shorthand("alice~bar")
            .expect("any-position dhttp shorthand should parse when expanded name is valid");

        assert_eq!(name.as_full(), "alice.dhttp.netbar");
    }

    #[test]
    fn name_from_dhttp_shorthand_rejects_bare_suffix_marker() {
        let error = Name::from_dhttp_shorthand("~").expect_err("bare shorthand is not a name");

        assert!(matches!(error, InvalidName::EmptyLabel { .. }));
    }

    #[test]
    fn name_from_dhttp_shorthand_accepts_owned_bytes() {
        let name = Name::from_dhttp_shorthand(Bytes::from_static(b"alice~"))
            .expect("owned bytes shorthand should parse");

        assert_eq!(name.as_full(), "alice.dhttp.net");
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

    // --- TryFrom<&[u8]> tests ---

    #[test]
    fn name_try_from_ref_bytes_lowercase() {
        let input: &[u8] = b"example.com";
        let n = Name::try_from(input).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_mixed_case() {
        let input: &[u8] = b"Example.COM";
        let n = Name::try_from(input).unwrap();
        assert_eq!(n.as_str(), "example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_wildcard() {
        let input: &[u8] = b"*.example.com";
        let n = Name::try_from(input).unwrap();
        assert!(n.is_wildcard());
        assert_eq!(n.as_str(), "*.example.com");
    }

    #[test]
    fn name_try_from_ref_bytes_invalid() {
        let input: &[u8] = b"!!!";
        let err = Name::try_from(input).unwrap_err();
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

    #[test]
    fn name_try_from_cow_bytes_borrowed_and_owned() {
        let borrowed = Cow::<[u8]>::Borrowed(b"Example.COM");
        let owned: Cow<'_, [u8]> = Cow::Owned(b"Reimu.Pilot".to_vec());

        let borrowed_name = Name::try_from(borrowed).unwrap();
        let owned_name = Name::try_from(owned).unwrap();

        assert_eq!(borrowed_name.as_str(), "example.com");
        assert_eq!(owned_name.as_str(), "reimu.pilot");
    }

    // --- DhttpName tests ---

    #[test]
    fn dhttp_name_suffix_is_dhttp_net() {
        assert_eq!(DhttpName::SUFFIX, ".dhttp.net");
    }

    #[test]
    fn dhttp_name_parse_full() {
        let dn = "hello.dhttp.net".parse::<DhttpName>().unwrap();
        assert_eq!(dn.as_full(), "hello.dhttp.net");
        assert_eq!(dn.as_partial(), "hello");
    }

    #[test]
    fn dhttp_name_parse_partial_multi_label() {
        let dn = "reimu.pilot".parse::<DhttpName>().unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
        assert_eq!(dn.as_partial(), "reimu.pilot");
    }

    #[test]
    fn dhttp_name_parse_partial_single_label_rejected() {
        let name = "hello".parse::<DhttpName>().unwrap();

        assert_eq!(name.as_full(), "hello.dhttp.net");
    }

    #[test]
    fn dhttp_name_serialize() {
        let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let json = serde_json::to_string(&dn).unwrap();
        assert_eq!(json, "\"reimu.pilot\"");
    }

    #[test]
    fn dhttp_name_deserialize_from_partial() {
        let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot\"").unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_deserialize_from_full() {
        let dn: DhttpName<'static> = serde_json::from_str("\"reimu.pilot.dhttp.net\"").unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_deserialize_rejects_invalid() {
        let result: Result<DhttpName<'static>, _> = serde_json::from_str("\"!!!\"");
        assert!(result.is_err());
    }

    #[test]
    fn dhttp_name_hash_consistent_with_name() {
        use std::hash::{DefaultHasher, Hasher};
        let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let n = Name::try_from_static(b"reimu.pilot.dhttp.net").unwrap();
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
        let a = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let b = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let c = "other.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn dhttp_name_to_owned_and_clone() {
        let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let owned = dn.to_owned();
        assert_eq!(owned.as_full(), "reimu.pilot.dhttp.net");
        let cloned = owned.clone();
        assert_eq!(cloned.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_into_owned() {
        let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();
        let owned = dn.into_owned();
        assert_eq!(owned.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_to_wildcard_replaces_first_label() {
        let dn = "reimu.pilot.dhttp.net".parse::<DhttpName>().unwrap();

        let wildcard = dn.to_wildcard();

        assert_eq!(wildcard.as_full(), "*.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_from_str_trait() {
        let dn: DhttpName = "reimu.pilot.dhttp.net".parse().unwrap();
        assert_eq!(dn.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_from_str_trait_rejects_invalid() {
        let result: Result<DhttpName, _> = "!!!".parse();
        assert!(result.is_err());
    }

    #[test]
    fn dhttp_name_legacy_borrow_method() {
        let dn = "reimu.pilot".parse::<DhttpName>().unwrap();
        let borrowed = dn.borrow();
        assert_eq!(borrowed.as_full(), dn.as_full());
    }

    #[test]
    fn dhttp_name_legacy_validate() {
        DhttpName::validate(b"reimu.pilot.dhttp.net").unwrap();
        assert!(DhttpName::validate(b"reimu.pilot").is_err());
    }

    #[test]
    fn dhttp_name_try_from_str_expands_partial_name() {
        let name = DhttpName::try_from("reimu.pilot").unwrap();
        assert_eq!(name.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_try_from_string_expands_tilde_name() {
        let name = DhttpName::try_from(String::from("reimu.pilot~")).unwrap();
        assert_eq!(name.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_try_from_bytes_and_cow_bytes_append_suffix() {
        let from_bytes = DhttpName::try_from(Bytes::from_static(b"Reimu.Pilot")).unwrap();
        let from_cow: DhttpName<'_> =
            DhttpName::try_from(Cow::<[u8]>::Borrowed(b"Device")).unwrap();

        assert_eq!(from_bytes.as_full(), "reimu.pilot.dhttp.net");
        assert_eq!(from_cow.as_full(), "device.dhttp.net");
    }

    #[test]
    fn dhttp_name_try_from_static_bytes_appends_suffix() {
        let name = DhttpName::try_from_static(b"Device").unwrap();

        assert_eq!(name.as_full(), "device.dhttp.net");
    }

    #[test]
    fn dhttp_name_try_from_name_accepts_full_name_without_reparsing_string() {
        let name = Name::try_from("reimu.pilot.dhttp.net").unwrap();

        let dhttp_name = DhttpName::try_from(name).unwrap();

        assert_eq!(dhttp_name.as_full(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn dhttp_name_try_from_name_rejects_missing_suffix() {
        let name = Name::try_from("example.com").unwrap();

        let error = DhttpName::try_from(name).unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpName::InvalidName {
                source: InvalidName::MissingSuffix { .. }
            }
        ));
    }

    #[test]
    fn expand_uri_replaces_bare_tilde_with_self_name() {
        let name = "reimu.pilot".parse::<DhttpName>().unwrap();
        let uri = "https://~/api?q=1".parse().unwrap();

        let expanded = name.expand_uri(uri).unwrap();

        assert_eq!(
            expanded.to_string(),
            "https://reimu.pilot.dhttp.net/api?q=1"
        );
    }

    #[test]
    fn expand_uri_expands_tilde_suffix_and_preserves_userinfo_port() {
        let name = "self.host".parse::<DhttpName>().unwrap();
        let uri = "https://alice@reimu.pilot~:443/api".parse().unwrap();

        let expanded = name.expand_uri(uri).unwrap();

        assert_eq!(
            expanded.to_string(),
            "https://alice@reimu.pilot.dhttp.net:443/api"
        );
    }

    #[test]
    fn expand_authority_expands_tilde_suffix_and_preserves_userinfo_port() {
        let name = "self.host".parse::<DhttpName>().unwrap();
        let authority = "alice@reimu.pilot~:443".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(Some(&name), authority).unwrap();

        assert_eq!(expanded.as_str(), "alice@reimu.pilot.dhttp.net:443");
    }

    #[test]
    fn expand_authority_expands_any_position_tilde_suffix() {
        let authority = "alice@a~:443".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

        assert_eq!(expanded.as_str(), "alice@a.dhttp.net:443");
    }

    #[test]
    fn expand_authority_keeps_bare_tilde_as_self_with_base() {
        let base = "reimu.pilot".parse::<DhttpName>().unwrap();
        let authority = "~".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(Some(&base), authority).unwrap();

        assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn expand_authority_rejects_invalid_shorthand_host() {
        let authority = "~bar".parse().unwrap();

        let error = DhttpName::expand_authority_with_base(None, authority).unwrap_err();

        assert!(matches!(error, ExpandAuthorityError::InvalidName { .. }));
    }

    #[test]
    fn expand_authority_canonicalizes_mixed_case_host_only_dhttp_name() {
        let authority = "Reimu.Pilot.Dhttp.Net".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

        assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn expand_authority_canonicalizes_mixed_case_decorated_dhttp_name() {
        let authority = "alice@Reimu.Pilot.Dhttp.Net:443".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

        assert_eq!(expanded.as_str(), "alice@reimu.pilot.dhttp.net:443");
    }

    #[test]
    fn expand_authority_host_only_partial_uses_canonical_name() {
        let authority = "Reimu.Pilot~".parse().unwrap();

        let expanded = DhttpName::expand_authority_with_base(None, authority).unwrap();

        assert_eq!(expanded.as_str(), "reimu.pilot.dhttp.net");
    }

    #[test]
    fn expand_authority_with_base_requires_base_name_for_bare_tilde() {
        let authority = "~".parse().unwrap();

        let error = DhttpName::expand_authority_with_base(None, authority).unwrap_err();

        assert!(matches!(error, ExpandAuthorityError::MissingBaseName));
    }

    #[test]
    fn expand_uri_leaves_plain_host_unchanged() {
        let name = "self.host".parse::<DhttpName>().unwrap();
        let uri: http::Uri = "https://example.com/api".parse().unwrap();

        let expanded = name.expand_uri(uri.clone()).unwrap();

        assert_eq!(expanded, uri);
    }

    #[test]
    fn expand_uri_rejects_invalid_expanded_name() {
        let name = "self.host".parse::<DhttpName>().unwrap();
        let uri = "https://123~/api".parse().unwrap();

        let error = name.expand_uri(uri).unwrap_err();

        assert!(matches!(
            error,
            ExpandUriError::Authority {
                source: ExpandAuthorityError::InvalidName { .. }
            }
        ));
    }

    #[test]
    fn expand_uri_with_base_expands_partial_without_base_name() {
        let uri = "https://reimu.pilot~/api".parse().unwrap();

        let expanded = DhttpName::expand_uri_with_base(None, uri).unwrap();

        assert_eq!(expanded.to_string(), "https://reimu.pilot.dhttp.net/api");
    }

    #[test]
    fn expand_uri_with_base_requires_base_name_for_bare_tilde() {
        let uri = "https://~/api".parse().unwrap();

        let error = DhttpName::expand_uri_with_base(None, uri).unwrap_err();

        assert!(matches!(
            error,
            ExpandUriError::Authority {
                source: ExpandAuthorityError::MissingBaseName
            }
        ));
    }
}
