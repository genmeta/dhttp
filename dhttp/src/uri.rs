use crate::{Error, Result};

/// Expand DHTTP authority shorthand before routing or delivering a request.
pub(crate) fn expand_uri_with_base(base: Option<&str>, uri: http::Uri) -> Result<http::Uri> {
    let mut parts = uri.into_parts();
    if let Some(authority) = parts.authority {
        parts.authority = Some(expand_authority_with_base(base, authority)?);
    }
    http::Uri::from_parts(parts).map_err(|error| Error::InvalidRequest {
        message: error.to_string(),
    })
}

fn expand_authority_with_base(
    base: Option<&str>,
    authority: http::uri::Authority,
) -> Result<http::uri::Authority> {
    let raw = authority.as_str();
    let host = authority.host();
    let replacement = if host == "~" {
        let base = base.ok_or_else(|| Error::InvalidRequest {
            message: "cannot expand bare dhttp shorthand without a base name".into(),
        })?;
        dhttp_home::normalize_name(base).ok_or_else(|| Error::InvalidRequest {
            message: "invalid local DHTTP name".into(),
        })?
    } else if host.contains('~') {
        let expanded = host.replace('~', dhttp_home::DHTTP_SUFFIX);
        let canonical = expanded.to_ascii_lowercase();
        if !dhttp_home::is_valid_dns_name(&canonical) {
            return Err(Error::InvalidRequest {
                message: format!("invalid DHTTP shorthand host: {host}"),
            });
        }
        canonical
    } else if host.len() >= dhttp_home::DHTTP_SUFFIX.len()
        && host.as_bytes()[host.len() - dhttp_home::DHTTP_SUFFIX.len()..]
            .eq_ignore_ascii_case(dhttp_home::DHTTP_SUFFIX.as_bytes())
    {
        dhttp_home::normalize_name(host).ok_or_else(|| Error::InvalidRequest {
            message: format!("invalid DHTTP authority host: {host}"),
        })?
    } else {
        return Ok(authority);
    };

    let expanded = if raw == host {
        replacement
    } else {
        let user_info_len = raw
            .split_once('@')
            .map(|(user_info, ..)| user_info.len() + 1)
            .unwrap_or_default();
        format!(
            "{user_info}{host}{port}",
            user_info = &raw[..user_info_len],
            host = replacement,
            port = &raw[user_info_len + host.len()..],
        )
    };
    expanded.parse().map_err(Error::from)
}

/// Return the expanded URI and canonical remote DHTTP name for outbound routing.
pub(crate) fn resolve_request_uri(local_name: &str, uri: http::Uri) -> Result<(http::Uri, String)> {
    let local = dhttp_home::normalize_name(local_name).ok_or_else(|| Error::InvalidRequest {
        message: "invalid local DHTTP name".into(),
    })?;
    let uri = expand_uri_with_base(Some(&local), uri)?;
    if let Some(scheme) = uri.scheme_str()
        && !matches!(scheme, "https" | "http" | "dhttp" | "wss" | "ws")
    {
        return Err(Error::InvalidRequest {
            message: "unsupported URI scheme".into(),
        });
    }
    let host = uri.host().ok_or_else(|| Error::InvalidRequest {
        message: "URI has no remote authority".into(),
    })?;
    let remote = dhttp_home::normalize_name(host).ok_or_else(|| Error::InvalidName {
        name: host.to_owned(),
    })?;
    Ok((uri, remote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_shorthand_and_identifies_remote() {
        let (uri, remote) = resolve_request_uri(
            "alice.dhttp.net",
            "https://bob~/upload?q=1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(uri.to_string(), "https://bob.dhttp.net/upload?q=1");
        assert_eq!(remote, "bob.dhttp.net");

        let (uri, remote) =
            resolve_request_uri("alice.dhttp.net", "https://~/self".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "https://alice.dhttp.net/self");
        assert_eq!(remote, "alice.dhttp.net");

        let (uri, remote) =
            resolve_request_uri("alice.dhttp.net", "https://Bob/x".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "https://Bob/x");
        assert_eq!(remote, "bob.dhttp.net");
    }

    #[test]
    fn preserves_decorated_authority_when_expanding() {
        let uri = "https://alice@Reimu.Pilot~:443/api".parse().unwrap();
        let expanded = expand_uri_with_base(Some("self.host"), uri).unwrap();
        assert_eq!(
            expanded.to_string(),
            "https://alice@reimu.pilot.dhttp.net:443/api"
        );
        let uri = "https://a~b/api".parse().unwrap();
        assert_eq!(
            expand_uri_with_base(None, uri).unwrap().to_string(),
            "https://a.dhttp.netb/api"
        );
    }

    #[test]
    fn rejects_invalid_request_authorities() {
        assert!(matches!(
            resolve_request_uri("alice", "ftp://bob~/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
        assert!(matches!(
            resolve_request_uri("alice", "/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
        assert!(matches!(
            resolve_request_uri("alice", "https://bad_name/x".parse().unwrap()),
            Err(Error::InvalidName { .. })
        ));
        assert!(matches!(
            expand_uri_with_base(None, "https://~/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
        assert!(matches!(
            expand_uri_with_base(None, "https://bad_name~/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
    }
}
