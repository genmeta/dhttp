use crate::{error::DhttpError, http as api_http};

pub type Result<T> = std::result::Result<T, DhttpError>;

pub struct ReadStream {
    inner: Option<h3x::server::ReadStream>,
}

impl ReadStream {
    pub(crate) fn new(inner: h3x::server::ReadStream) -> Self {
        Self { inner: Some(inner) }
    }

    pub async fn read_data_frame_chunk(&mut self) -> Result<Option<api_http::Body>> {
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("read_stream.read_data_frame_chunk", "read stream is closed")
        })?;
        stream
            .try_stream_io(async |stream| stream.read_data_frame_chunk().await)
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|error| DhttpError::from_error("read_stream.read_data_frame_chunk", error))
    }

    pub async fn read_header_frame(&mut self) -> Result<Option<api_http::HeaderFrame>> {
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("read_stream.read_header_frame", "read stream is closed")
        })?;
        stream
            .try_stream_io(async |stream| stream.read_header_frame().await)
            .await
            .map(|headers| headers.map(field_section_to_frame))
            .map_err(|error| DhttpError::from_error("read_stream.read_header_frame", error))
    }

    pub async fn stop(&mut self, code: u64) -> Result<()> {
        let code = crate::endpoint::code_from_u64("read_stream.stop", code)?;
        let stream = self
            .inner
            .as_mut()
            .ok_or_else(|| DhttpError::from_message("read_stream.stop", "read stream is closed"))?;
        stream
            .stop(code)
            .await
            .map_err(|error| DhttpError::from_error("read_stream.stop", error))?;
        self.inner = None;
        Ok(())
    }
}

pub(crate) fn field_section_to_frame(
    section: h3x::qpack::field::FieldSection,
) -> api_http::HeaderFrame {
    section
        .iter()
        .map(|field| (field.name.as_ref().to_vec(), field.value.as_ref().to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::field_section_to_frame;

    #[test]
    fn field_section_to_frame_preserves_non_utf8_header_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert("x-bin", HeaderValue::from_bytes(b"\xff").unwrap());
        let section = h3x::qpack::field::FieldSection::trailer(headers);

        assert_eq!(
            field_section_to_frame(section),
            vec![(b"x-bin".to_vec(), b"\xff".to_vec())]
        );
    }
}
