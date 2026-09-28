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
    AlreadyListening,
    NameInUse {
        name: String,
    },
    NetworkNotInitialized,
    AlreadyInitialized,
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
            Self::AlreadyListening => f.write_str("endpoint is already listening"),
            Self::NameInUse { name } => write!(f, "name is already registered: {name}"),
            Self::NetworkNotInitialized => f.write_str("network is not initialized"),
            Self::AlreadyInitialized => f.write_str("network is already initialized"),
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

impl From<http::uri::InvalidUri> for Error {
    fn from(source: http::uri::InvalidUri) -> Self {
        Self::InvalidUri {
            source: Arc::new(source),
        }
    }
}
