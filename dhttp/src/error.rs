use std::{fmt, path::PathBuf, sync::Arc};

pub type Result<T> = std::result::Result<T, Error>;

/// DHTTP error categories with their original source errors.
/// Source errors are shared so request results and status observers retain the
/// same cause. Display/Error and conversion behavior are not implemented.
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
    EndpointClosed,
    NetworkClosed,
    NetworkUnavailable,
    NetworkNotInitialized,
    AlreadyInitialized,
    InvalidNetworkConfig {
        message: String,
    },
    HomeUnavailable {
        message: String,
    },
    IdentityNotFound {
        name: String,
    },
    Credentials {
        source: Arc<qtls::RustlsError>,
    },
    TlsConfig {
        source: Arc<qtls::TlsConfigError>,
    },
    Http {
        source: Arc<http::Error>,
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
    NetworkIo {
        device: String,
        source: Arc<std::io::Error>,
    },
    Resolve {
        name: String,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    Publish {
        name: String,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    Cancelled,
    Home {
        path: PathBuf,
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("format the DHTTP error without discarding its category")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        todo!("expose the original source error")
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(source: http::uri::InvalidUri) -> Self {
        Self::InvalidUri {
            source: Arc::new(source),
        }
    }
}

/// Drain outcome, including cleanup forced by reaching the absolute deadline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    pub forced_connections: usize,
    pub cancelled_exchanges: usize,
    pub unfinished_tasks: usize,
}
