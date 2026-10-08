use std::{fmt, sync::Arc};

pub type Result<T> = std::result::Result<T, Error>;

/// Stable categories for language adapters; never classified from error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidArgument,
    Identity,
    RemoteIdentityChanged,
    AlreadyListening,
    Network,
    Protocol,
    Io,
    Cancelled,
    Closed,
    DeadlineExceeded,
    BodyInUse,
    Producer,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "ERR_INVALID_ARGUMENT",
            Self::Identity => "ERR_IDENTITY",
            Self::RemoteIdentityChanged => "ERR_REMOTE_IDENTITY_CHANGED",
            Self::AlreadyListening => "ERR_ALREADY_LISTENING",
            Self::Network => "ERR_NETWORK",
            Self::Protocol => "ERR_PROTOCOL",
            Self::Io => "ERR_IO",
            Self::Cancelled => "ERR_CANCELLED",
            Self::Closed => "ERR_CLOSED",
            Self::DeadlineExceeded => "ERR_DEADLINE_EXCEEDED",
            Self::BodyInUse => "ERR_BODY_IN_USE",
            Self::Producer => "ERR_PRODUCER",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub protocol_code: Option<u64>,
    cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            protocol_code: None,
            cause: None,
        }
    }

    pub fn producer(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            code: ErrorCode::Producer,
            message: cause.to_string(),
            protocol_code: None,
            cause: Some(Arc::new(cause)),
        }
    }

    pub(crate) fn cancelled() -> Self {
        Self::new(ErrorCode::Cancelled, "operation cancelled")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|cause| cause as _)
    }
}

impl From<dhttp::Error> for Error {
    fn from(cause: dhttp::Error) -> Self {
        use dhttp::Error as Core;
        if let Core::Io { source } = &cause
            && let Some(error) = source
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<Self>())
        {
            return error.clone();
        }
        let code = match &cause {
            Core::InvalidName { .. } | Core::InvalidRequest { .. } | Core::InvalidUri { .. } => {
                ErrorCode::InvalidArgument
            }
            Core::RemoteIdentityChanged => ErrorCode::RemoteIdentityChanged,
            Core::AlreadyListening | Core::NameInUse { .. } => ErrorCode::AlreadyListening,
            Core::HomeUnavailable { .. }
            | Core::Home { .. }
            | Core::Credentials { .. }
            | Core::TlsConfig { .. } => ErrorCode::Identity,
            Core::NetworkNotInitialized | Core::Quic { .. } => ErrorCode::Network,
            Core::Http3 { .. } => ErrorCode::Protocol,
            Core::Io { .. } => ErrorCode::Io,
        };
        let protocol_code = match &cause {
            Core::Http3 { source } => Some(source.code.as_u64()),
            _ => None,
        };
        Self {
            code,
            message: cause.to_string(),
            protocol_code,
            cause: Some(Arc::new(cause)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(cause: std::io::Error) -> Self {
        Self::from(dhttp::Error::from(cause))
    }
}

impl From<dhttp::BoxError> for Error {
    fn from(cause: dhttp::BoxError) -> Self {
        match cause.downcast::<Self>() {
            Ok(error) => *error,
            Err(cause) => Self::from(dhttp::Error::from(cause)),
        }
    }
}
