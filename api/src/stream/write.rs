use bytes::Bytes;

use crate::{error::DhttpError, http as api_http};

pub type Result<T> = std::result::Result<T, DhttpError>;

pub struct WriteStream {
    inner: Option<h3x::dhttp::message::MessageWriter>,
}

impl WriteStream {
    pub(crate) fn new(inner: h3x::dhttp::message::MessageWriter) -> Self {
        Self { inner: Some(inner) }
    }

    pub async fn send_header(&mut self, headers: api_http::HeaderFrame) -> Result<()> {
        let fields = pairs_to_field_lines(headers);
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.send_header", "write stream is closed")
        })?;
        stream
            .write_header(fields)
            .await
            .map_err(|error| DhttpError::from_error("write_stream.send_header", error))
    }

    pub async fn send_data(&mut self, data: api_http::Body) -> Result<()> {
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.send_data", "write stream is closed")
        })?;
        stream
            .write_data(Bytes::from(data))
            .await
            .map_err(|error| DhttpError::from_error("write_stream.send_data", error))
    }

    pub async fn flush(&mut self) -> Result<()> {
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.flush", "write stream is closed")
        })?;
        stream
            .flush()
            .await
            .map_err(|error| DhttpError::from_error("write_stream.flush", error))
    }

    pub async fn close(&mut self) -> Result<()> {
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.close", "write stream is closed")
        })?;
        stream
            .close()
            .await
            .map_err(|error| DhttpError::from_error("write_stream.close", error))?;
        self.inner = None;
        Ok(())
    }

    pub async fn reset(&mut self, code: u64) -> Result<()> {
        let code = crate::endpoint::code_from_u64("write_stream.reset", code)?;
        let stream = self.inner.as_mut().ok_or_else(|| {
            DhttpError::from_message("write_stream.reset", "write stream is closed")
        })?;
        stream
            .reset(code)
            .await
            .map_err(|error| DhttpError::from_error("write_stream.reset", error))?;
        self.inner = None;
        Ok(())
    }
}

fn pairs_to_field_lines(headers: api_http::HeaderFrame) -> Vec<h3x::qpack::field::FieldLine> {
    headers
        .into_iter()
        .map(|(name, value)| h3x::qpack::field::FieldLine {
            name: Bytes::from(name),
            value: Bytes::from(value),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::pairs_to_field_lines;

    #[test]
    fn pairs_to_field_lines_preserves_non_utf8_header_bytes() {
        let fields = pairs_to_field_lines(vec![(b"x-bin".to_vec(), b"\xff".to_vec())]);

        assert_eq!(fields[0].name.as_ref(), b"x-bin");
        assert_eq!(fields[0].value.as_ref(), b"\xff");
    }
}
