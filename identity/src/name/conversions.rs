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
