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
