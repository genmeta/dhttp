use bytes::Bytes;
use tokio::sync::Mutex;

use crate::{error::DhttpError, http as api_http};

pub type Result<T> = std::result::Result<T, DhttpError>;

pub struct WriteStream {
    inner: Mutex<Option<h3x::server::WriteStream>>,
}

impl WriteStream {
    pub(crate) fn new(inner: h3x::server::WriteStream) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    pub async fn send_header(&self, headers: api_http::HeaderPairs) -> Result<()> {
        let fields = pairs_to_field_lines(headers);
        let mut guard = self.inner.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.send_header", "write stream is closed")
        })?;
        stream
            .write_header(fields)
            .await
            .map_err(|error| DhttpError::from_error("write_stream.send_header", error))
    }

    pub async fn send_data(&self, data: api_http::Body) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.send_data", "write stream is closed")
        })?;
        stream
            .write_data(Bytes::from(data))
            .await
            .map_err(|error| DhttpError::from_error("write_stream.send_data", error))
    }

    pub async fn flush(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.flush", "write stream is closed")
        })?;
        stream
            .flush()
            .await
            .map_err(|error| DhttpError::from_error("write_stream.flush", error))
    }

    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let mut stream = guard.take().ok_or_else(|| {
            DhttpError::from_message("write_stream.close", "write stream is closed")
        })?;
        stream
            .close()
            .await
            .map_err(|error| DhttpError::from_error("write_stream.close", error))
    }

    pub async fn cancel(&self, code: u64) -> Result<()> {
        let code = crate::endpoint::code_from_u64("write_stream.cancel", code)?;
        let mut guard = self.inner.lock().await;
        let mut stream = guard.take().ok_or_else(|| {
            DhttpError::from_message("write_stream.cancel", "write stream is closed")
        })?;
        stream
            .cancel(code)
            .await
            .map_err(|error| DhttpError::from_error("write_stream.cancel", error))
    }
}

fn pairs_to_field_lines(headers: api_http::HeaderPairs) -> Vec<h3x::qpack::field::FieldLine> {
    headers
        .into_iter()
        .map(|(name, value)| h3x::qpack::field::FieldLine {
            name: Bytes::from(name),
            value: Bytes::from(value),
        })
        .collect()
}
