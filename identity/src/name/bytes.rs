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
