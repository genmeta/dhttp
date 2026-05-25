use tokio::sync::Mutex;

use crate::{error::DhttpError, http as api_http};

pub type Result<T> = std::result::Result<T, DhttpError>;

pub struct ReadStream {
    inner: Mutex<Option<h3x::server::ReadStream>>,
}

impl ReadStream {
    pub(crate) fn new(inner: h3x::server::ReadStream) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    pub async fn read_data_frame_chunk(&self) -> Result<Option<api_http::Body>> {
        let mut guard = self.inner.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("read_stream.read_data_frame_chunk", "read stream is closed")
        })?;
        stream
            .read_data_chunk()
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|error| DhttpError::from_error("read_stream.read_data_frame_chunk", error))
    }

    pub async fn read_header_frame(&self) -> Result<Option<api_http::HeaderPairs>> {
        let mut guard = self.inner.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("read_stream.read_header_frame", "read stream is closed")
        })?;
        stream
            .read_header()
            .await
            .map(|headers| headers.map(field_section_to_pairs))
            .map_err(|error| DhttpError::from_error("read_stream.read_header_frame", error))
    }

    pub async fn stop(&self, code: u64) -> Result<()> {
        let code = crate::endpoint::code_from_u64("read_stream.stop", code)?;
        let mut guard = self.inner.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| DhttpError::from_message("read_stream.stop", "read stream is closed"))?;
        stream
            .stop(code)
            .await
            .map_err(|error| DhttpError::from_error("read_stream.stop", error))
    }
}

pub(crate) fn field_section_to_pairs(
    section: h3x::qpack::field::FieldSection,
) -> api_http::HeaderPairs {
    section
        .iter()
        .map(|field| {
            (
                String::from_utf8_lossy(field.name.as_ref()).into_owned(),
                String::from_utf8_lossy(field.value.as_ref()).into_owned(),
            )
        })
        .collect()
}
