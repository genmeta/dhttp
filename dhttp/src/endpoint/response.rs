use super::{BODY_WINDOW_BYTES, body::forward_outbound_body};
use crate::{BoxError, Error, Result};
use bytes::Bytes;
use h3x::WriteResponse;

pub(super) async fn send_response<B, W>(
    response: http::Response<B>,
    method: http::Method,
    writer: W,
    qpack: h3x::ArcQpack,
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
    W: WriteResponse,
{
    let (parts, body) = response.into_parts();
    let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
    let outgoing = h3x::Response::<h3x::W>::from_parts(parts, buffer.clone());
    // h3x suppresses these bodies on the wire; do not poll their sources.
    if method == http::Method::HEAD
        || outgoing.status() == http::StatusCode::NO_CONTENT
        || outgoing.status() == http::StatusCode::NOT_MODIFIED
    {
        drop(body);
        let result = writer
            .write_response(outgoing, method, qpack)
            .await
            .map_err(Error::from);
        return match result {
            Err(Error::Http3 { source }) if source.code == h3x::ErrorCode::NoError => Ok(()),
            result => result,
        };
    }
    let trailers = outgoing.clone();
    let writing = async move {
        writer
            .write_response(outgoing, method, qpack)
            .await
            .map_err(Error::from)
    };
    let forwarding = forward_outbound_body(body, buffer, move |name, value| {
        trailers.append_trailer(name, value);
    });
    let result = tokio::try_join!(biased; writing, forwarding).map(|_| ());
    match result {
        Ok(_) => Ok(()),
        // The peer can decline the rest of a response body without failing the exchange.
        Err(Error::Http3 { source }) if source.code == h3x::ErrorCode::NoError => Ok(()),
        Err(error) => Err(error),
    }
}
