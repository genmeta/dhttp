//! Transport-independent tests: all HTTP/3 traffic stays inside Tokio duplex streams.
use super::*;
use http_body_util::{Empty, Full};
#[path = "../support/transport.rs"]
mod support;

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("in-memory exchange must finish")
}
fn handshake() -> Arc<qtls::HandshakeSummary> {
    Arc::new(qtls::HandshakeSummary {
        local: None,
        remote: None,
        alpn: Some(Bytes::from_static(h3x::ALPN)),
    })
}
fn pending_body(dropped: tokio::sync::oneshot::Sender<()>) -> Body {
    let guard = scopeguard::guard(dropped, |sender| {
        let _ = sender.send(());
    });
    let stream = async_stream::stream! {
        let _guard = guard;
        std::future::pending::<()>().await;
        yield Ok::<_, BoxError>(Frame::data(Bytes::new()));
    };
    StreamBody::new(stream).boxed_unsync()
}
fn frames_body(data: &'static [u8]) -> Body {
    let mut trailers = http::HeaderMap::new();
    trailers.append("x-tag", http::HeaderValue::from_static("one"));
    trailers.append("x-tag", http::HeaderValue::from_static("two"));
    StreamBody::new(futures::stream::iter([
        Ok::<_, BoxError>(Frame::data(Bytes::from_static(data))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed_unsync()
}

include!("endpoint/request.rs");
include!("endpoint/body.rs");
include!("endpoint/cancellation.rs");
