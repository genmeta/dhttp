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

/// Return the expanded URI and DNS authority used for outbound routing.
/// Only explicit DHTTP shorthand expands a hostname; ordinary DNS names stay intact.
pub(crate) fn resolve_request_uri(
    local_name: Option<&str>,
    uri: http::Uri,
) -> Result<(http::Uri, String)> {
    let uri = expand_uri_with_base(local_name, uri)?;
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
    if host.contains('_')
        || !matches!(
            qtls::ServerName::try_from(host),
            Ok(qtls::ServerName::DnsName(_))
        )
    {
        return Err(Error::InvalidName {
            name: host.to_owned(),
        });
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.ends_with(dhttp_home::DHTTP_SUFFIX) {
        // DHTTP's :sequence stays in the URI. Its transport port comes from E records.
        return Ok((uri, host));
    }
    // Authority accepts port strings outside u16; reject those before connecting.
    let authority = uri.authority().expect("a URI host has an authority");
    let target = authority.as_str().rsplit('@').next().unwrap();
    let remote = match target.rsplit_once(':') {
        Some((_, port)) => {
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| Error::InvalidRequest {
                    message: "URI port must be between 1 and 65535".into(),
                })?;
            format!("{host}:{port}")
        }
        None => host,
    };
    Ok((uri, remote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_shorthand_and_identifies_remote() {
        let (uri, remote) = resolve_request_uri(
            Some("alice.dhttp.net"),
            "https://bob~/upload?q=1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(uri.to_string(), "https://bob.dhttp.net/upload?q=1");
        assert_eq!(remote, "bob.dhttp.net");

        let (uri, remote) =
            resolve_request_uri(Some("alice.dhttp.net"), "https://~/self".parse().unwrap())
                .unwrap();
        assert_eq!(uri.to_string(), "https://alice.dhttp.net/self");
        assert_eq!(remote, "alice.dhttp.net");

        let (uri, remote) =
            resolve_request_uri(Some("alice.dhttp.net"), "https://Bob/x".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "https://Bob/x");
        assert_eq!(remote, "bob");
    }

    #[test]
    fn preserves_dns_origins_and_ports_for_bootstrap() {
        for (input, expected) in [
            ("https://ddns.genmeta.net/api/v2/lookup", "ddns.genmeta.net"),
            (
                "https://DDNS.Genmeta.Net:4433/api/v2/publish",
                "ddns.genmeta.net:4433",
            ),
            ("https://localhost:8443/lookup", "localhost:8443"),
            (
                "https://ddns.genmeta.net.:443/lookup",
                "ddns.genmeta.net:443",
            ),
        ] {
            let (_, remote) = resolve_request_uri(None, input.parse().unwrap()).unwrap();
            assert_eq!(remote, expected);
        }
    }

    #[test]
    fn dhttp_sequence_is_preserved_without_becoming_a_transport_port() {
        let (uri, remote) =
            resolve_request_uri(None, "https://bob~:70000/x".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "https://bob.dhttp.net:70000/x");
        assert_eq!(remote, "bob.dhttp.net");
    }

    #[test]
    fn rejects_unusable_dns_origins_before_connecting() {
        for input in [
            "https://ddns.genmeta.net:70000/lookup",
            "https://ddns.genmeta.net:0/lookup",
            "https://ddns.genmeta.net:/lookup",
            "https://127.0.0.1:4433/lookup",
            "https://[::1]:4433/lookup",
            "https://bad_name.example/lookup",
            "https://ddns.genmeta.net../lookup",
        ] {
            assert!(
                resolve_request_uri(None, input.parse().unwrap()).is_err(),
                "{input}"
            );
        }
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
            resolve_request_uri(Some("alice"), "ftp://bob~/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
        assert!(matches!(
            resolve_request_uri(Some("alice"), "/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
        assert!(matches!(
            resolve_request_uri(Some("alice"), "https://bad_name/x".parse().unwrap()),
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

    #[test]
    fn anonymous_requests_resolve_remote_names_without_a_local_base() {
        let (uri, remote) = resolve_request_uri(None, "https://bob~/x".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "https://bob.dhttp.net/x");
        assert_eq!(remote, "bob.dhttp.net");
        assert!(matches!(
            resolve_request_uri(None, "https://~/x".parse().unwrap()),
            Err(Error::InvalidRequest { .. })
        ));
    }
}
