use super::*;
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
