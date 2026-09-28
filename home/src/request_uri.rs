use dhttp_identity::name::{DhttpName, ExpandUriError, InvalidDhttpName};
use snafu::Snafu;

use crate::normalize_name;

#[derive(Debug, Snafu)]
pub enum ResolveRequestUriError {
    #[snafu(display("{source}"))]
    InvalidLocalName { source: InvalidDhttpName },
    #[snafu(display("{source}"))]
    ExpandUri { source: ExpandUriError },
    #[snafu(display("unsupported URI scheme"))]
    UnsupportedScheme,
    #[snafu(display("URI has no remote authority"))]
    MissingRemoteAuthority,
    #[snafu(display("invalid remote DHTTP name: {name}"))]
    InvalidRemoteName { name: String },
}

/// Expand DHTTP URI shorthand and return the canonical remote name for routing.
///
/// `local_name` is the sending endpoint's DHTTP name. The URI retains its
/// original authority when no shorthand expansion is needed.
pub fn resolve_request_uri(
    local_name: &str,
    uri: http::Uri,
) -> Result<(http::Uri, String), ResolveRequestUriError> {
    let local = DhttpName::try_from(local_name)
        .map_err(|source| ResolveRequestUriError::InvalidLocalName { source })?;
    let uri = local
        .expand_uri(uri)
        .map_err(|source| ResolveRequestUriError::ExpandUri { source })?;
    if let Some(scheme) = uri.scheme_str()
        && !matches!(scheme, "https" | "http" | "dhttp" | "wss" | "ws")
    {
        return Err(ResolveRequestUriError::UnsupportedScheme);
    }
    let host = uri
        .host()
        .ok_or(ResolveRequestUriError::MissingRemoteAuthority)?;
    let remote_name =
        normalize_name(host).ok_or_else(|| ResolveRequestUriError::InvalidRemoteName {
            name: host.to_owned(),
        })?;
    Ok((uri, remote_name))
}
