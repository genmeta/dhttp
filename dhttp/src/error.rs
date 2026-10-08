use std::{fmt, path::PathBuf, sync::Arc};

pub type Result<T> = std::result::Result<T, Error>;

/// DHTTP error categories with their original source errors.
/// Cloned errors retain their original source without adding lifecycle state.
#[derive(Clone, Debug)]
pub enum Error {
    InvalidName {
        name: String,
    },
    InvalidRequest {
        message: String,
    },
    InvalidUri {
        source: Arc<http::uri::InvalidUri>,
    },
    RemoteIdentityChanged,
    AlreadyListening,
    NameInUse {
        name: String,
    },
    NetworkNotInitialized,
    HomeUnavailable {
        message: String,
    },
    Credentials {
        source: Arc<qtls::RustlsError>,
    },
    TlsConfig {
        source: Arc<qtls::TlsConfigError>,
    },
    Http3 {
        source: Arc<h3x::Error>,
    },
    Quic {
        source: Arc<qconn::Error>,
    },
    Io {
        source: Arc<std::io::Error>,
    },
    Home {
        path: PathBuf,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { name } => write!(f, "invalid DHTTP name: {name}"),
            Self::InvalidRequest { message } => write!(f, "invalid request: {message}"),
            Self::RemoteIdentityChanged => f.write_str("remote identity changed"),
            Self::AlreadyListening => f.write_str("endpoint is already listening"),
            Self::NameInUse { name } => write!(f, "name is already registered: {name}"),
            Self::NetworkNotInitialized => f.write_str("network is not initialized"),
            Self::HomeUnavailable { message } => write!(f, "DHTTP home unavailable: {message}"),
            Self::Home { path, source } => write!(f, "{}: {source}", path.display()),
            Self::InvalidUri { source } => write!(f, "invalid URI: {source}"),
            Self::Credentials { source } => write!(f, "credentials: {source}"),
            Self::TlsConfig { source } => write!(f, "TLS configuration: {source}"),
            Self::Http3 { source } => write!(f, "HTTP/3: {source}"),
            Self::Quic { source } => write!(f, "QUIC: {source}"),
            Self::Io { source } => write!(f, "I/O: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUri { source } => Some(source.as_ref()),
            Self::Credentials { source } => Some(source.as_ref()),
            Self::TlsConfig { source } => Some(source.as_ref()),
            Self::Http3 { source } => Some(source.as_ref()),
            Self::Quic { source } => Some(source.as_ref()),
            Self::Io { source } => Some(source.as_ref()),
            Self::Home { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl Error {
    // Body and AsyncWrite erase concrete errors into BoxError/io::Error.
    // Recover core categories here so callers need only one error mapping.
    fn recover(source: &(dyn std::error::Error + 'static)) -> Option<Self> {
        if let Some(error) = source.downcast_ref::<Self>() {
            return Some(error.clone());
        }
        if let Some(error) = source.downcast_ref::<h3x::Error>() {
            return Some(error.clone().into());
        }
        if let Some(error) = source.downcast_ref::<qconn::Error>() {
            return Some(error.clone().into());
        }
        source
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .and_then(|source| Self::recover(source))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(source: http::uri::InvalidUri) -> Self {
        Self::InvalidUri {
            source: Arc::new(source),
        }
    }
}

impl From<h3x::Error> for Error {
    fn from(source: h3x::Error) -> Self {
        Self::Http3 {
            source: Arc::new(source),
        }
    }
}

impl From<qconn::Error> for Error {
    fn from(source: qconn::Error) -> Self {
        Self::Quic {
            source: Arc::new(source),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::recover(&source).unwrap_or_else(|| Self::Io {
            source: Arc::new(source),
        })
    }
}

impl From<crate::BoxError> for Error {
    fn from(source: crate::BoxError) -> Self {
        Self::recover(source.as_ref()).unwrap_or_else(|| Self::Io {
            source: Arc::new(std::io::Error::other(source)),
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/error.rs"]
mod tests;
