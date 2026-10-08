use dhttp_api::{Error, ErrorCode, upload_channel};
use futures::FutureExt;
use http::{HeaderMap, HeaderValue};
use http_body_util::BodyExt;

#[tokio::test]
async fn large_producer_is_backpressured_and_keeps_all_bytes_and_duplicate_trailers() {
    let (writer, mut body) = upload_channel();
    let bytes = vec![42u8; 512 * 1024];
    let mut sending = Box::pin(writer.send(&bytes));
    assert!(futures::poll!(&mut sending).is_pending());
    // Four chunks fit; the fifth cannot enter before consumption.
    for _ in 0..4 {
        let frame = body.frame().now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(frame.data_ref().unwrap().len(), 16 * 1024);
    }
    assert!(body.frame().now_or_never().is_none());
    let (sent, received) = tokio::join!(
        async {
            sending.await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.append("x-end", HeaderValue::from_static("one"));
            trailers.append("x-end", HeaderValue::from_static("two"));
            writer.finish(trailers).await.unwrap();
        },
        async {
            let collected = body.collect().await.unwrap();
            let trailers = collected.trailers().unwrap();
            assert_eq!(trailers.get_all("x-end").iter().count(), 2);
            collected.to_bytes()
        }
    );
    assert_eq!(sent, ());
    assert_eq!(received.len(), bytes.len() - 64 * 1024);
    assert!(received.iter().all(|byte| *byte == 42));
    assert_eq!(
        writer.send(b"late").await.unwrap_err().code,
        ErrorCode::Closed
    );
}

#[tokio::test]
async fn abandoned_or_failed_producer_is_not_normal_eof() {
    let (writer, mut body) = upload_channel();
    drop(writer);
    assert_eq!(
        body.frame().await.unwrap().unwrap_err().code,
        ErrorCode::Producer
    );
    assert!(body.frame().await.is_none());
    let (writer, mut body) = upload_channel();
    writer.fail(Error::producer(std::io::Error::other("producer failed")));
    let error = body.frame().await.unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::Producer);
    assert_eq!(error.message, "producer failed");
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn cancelling_a_partly_sent_chunk_terminates_the_upload() {
    let (writer, mut body) = upload_channel();
    let bytes = vec![0; 512 * 1024];
    let mut sending = Box::pin(writer.send(&bytes));
    assert!(futures::poll!(&mut sending).is_pending());
    drop(sending);
    assert_eq!(
        body.frame().await.unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn closed_consumer_unblocks_a_waiting_producer() {
    let (writer, body) = upload_channel();
    let bytes = vec![0; 512 * 1024];
    let mut sending = Box::pin(writer.send(&bytes));
    assert!(futures::poll!(&mut sending).is_pending());
    drop(body);
    assert_eq!(sending.await.unwrap_err().code, ErrorCode::Closed);
}
