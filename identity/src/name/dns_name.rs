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
