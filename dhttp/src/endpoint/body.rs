use super::BODY_READ_CHUNK_BYTES;
use crate::{BoxError, Result};
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::AsyncWriteExt;

// Expose the receive window as a pull-based stream of standard HTTP body frames.
pub(super) fn forward_inbound_body(
    inbound: h3x::ArcWndBuf,
    trailers: h3x::Trailers,
) -> impl futures::Stream<Item = Result<Frame<Bytes>>> + Send {
    let inbound = scopeguard::guard(inbound, |mut inbound| {
        inbound.stop(h3x::ErrorCode::NoError.as_u64());
    });
    async_stream::try_stream! {
        let inbound = inbound;
        loop {
            let bytes = inbound.read_chunk(BODY_READ_CHUNK_BYTES).await?;
            if bytes.is_empty() { break; }
            yield Frame::data(bytes);
        }
        let _ = scopeguard::ScopeGuard::into_inner(inbound);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    }
}

// The application Body produces frames; h3x consumes a byte window and shared
// trailers. A producer error cancels the shared window, waking the h3x writer.
pub(super) async fn forward_outbound_body<B>(
    src: B,
    mut dst: h3x::ArcWndBuf,
    mut append_trailer: impl FnMut(http::HeaderName, http::HeaderValue),
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let mut body = Box::pin(src);
    loop {
        let frame: Option<std::result::Result<Frame<Bytes>, BoxError>> =
            body.frame().await.map(|frame| frame.map_err(Into::into));
        let frame = match frame {
            None => break,
            Some(Ok(frame)) => frame,
            Some(Err(error)) => {
                // Only a source Body failure needs an explicit stream reset.
                dst.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
                return Err(error.into());
            }
        };
        match frame.into_data() {
            Ok(data) => dst
                .write_bytes(data)
                .await
                .map_err(h3x::Error::from_stream_io)?,
            Err(frame) => {
                if let Ok(fields) = frame.into_trailers() {
                    for (name, value) in fields.iter() {
                        append_trailer(name.clone(), value.clone());
                    }
                }
            }
        }
    }
    dst.shutdown().await.map_err(h3x::Error::from_stream_io)?;
    Ok(())
}
