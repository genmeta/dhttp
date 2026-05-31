use std::sync::Arc;

use crate::{
    authority::{LocalAuthority, RemoteAuthority},
    error::DhttpError,
    stream::{ReadStream, WriteStream},
};

pub type Result<T> = std::result::Result<T, DhttpError>;

type CoreConnection = h3x::connection::Connection<h3x::dquic::connection::Connection>;

#[derive(Clone)]
pub struct Connection {
    inner: Arc<CoreConnection>,
}

impl Connection {
    pub(crate) fn new(inner: Arc<CoreConnection>) -> Self {
        Self { inner }
    }

    pub async fn open_request_stream(&self) -> Result<(ReadStream, WriteStream)> {
        self.inner
            .initial_message_stream()
            .await
            .map(|(read, write)| (ReadStream::new(read), WriteStream::new(write)))
            .map_err(|error| DhttpError::from_error("connection.open_request_stream", error))
    }

    pub async fn local_authority(&self) -> Result<Option<LocalAuthority>> {
        self.inner
            .local_authority()
            .await
            .map(|opt| opt.map(LocalAuthority::new))
            .map_err(|error| DhttpError::from_error("connection.local_authority", error))
    }

    pub async fn remote_authority(&self) -> Result<Option<RemoteAuthority>> {
        self.inner
            .remote_authority()
            .await
            .map(|opt| opt.map(RemoteAuthority::new))
            .map_err(|error| DhttpError::from_error("connection.remote_authority", error))
    }
}
