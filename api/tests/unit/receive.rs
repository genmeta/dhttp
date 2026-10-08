use super::*;
use futures::{StreamExt, stream};
use http_body_util::{Full, StreamBody};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[tokio::test]
async fn demand_drives_native_body_and_preserves_duplicate_trailers() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counted = polls.clone();
    let mut trailers = HeaderMap::new();
    trailers.append("x-end", "one".parse().unwrap());
    trailers.append("x-end", "two".parse().unwrap());
    let frames = vec![
        Ok::<_, Error>(Frame::data(Bytes::from_static(b"abc"))),
        Ok(Frame::trailers(trailers)),
    ];
    let body = StreamBody::new(stream::iter(frames).inspect(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
    }));
    let (reader, worker) = BodyReader::bridge(body, OperationState::new());
    let task = tokio::spawn(worker);
    tokio::task::yield_now().await;
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(reader.next().await.unwrap().unwrap(), "abc");
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(reader.next().await.unwrap().is_none());
    assert_eq!(
        reader
            .trailers()
            .await
            .unwrap()
            .get_all("x-end")
            .iter()
            .count(),
        2
    );
    assert!(reader.next().await.unwrap().is_none());
    assert!(task.await.unwrap().is_ok());
}

struct PendingBody(Arc<AtomicBool>);
impl Body for PendingBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        Poll::Pending
    }
}
impl Drop for PendingBody {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn simultaneous_read_is_rejected_and_cancel_releases_native_body() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (reader, worker) = BodyReader::bridge(PendingBody(dropped.clone()), OperationState::new());
    let task = tokio::spawn(worker);
    let mut reading = Box::pin(reader.next());
    assert!(futures::poll!(&mut reading).is_pending());
    assert_eq!(reader.next().await.unwrap_err().code, ErrorCode::BodyInUse);
    reader.cancel();
    assert_eq!(reading.await.unwrap_err().code, ErrorCode::Cancelled);
    assert_eq!(
        reader.trailers().await.unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert_eq!(task.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancelling_a_read_future_cancels_native_consumption() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (reader, worker) = BodyReader::bridge(PendingBody(dropped.clone()), OperationState::new());
    let task = tokio::spawn(worker);
    let mut reading = Box::pin(reader.next());
    assert!(futures::poll!(&mut reading).is_pending());
    drop(reading);
    assert_eq!(task.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn dropping_a_reader_without_polling_it_releases_native_body() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (reader, worker) = BodyReader::bridge(PendingBody(dropped.clone()), OperationState::new());
    let task = tokio::spawn(worker);
    drop(reader);
    assert!(task.await.unwrap().is_err());
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn receive_errors_preserve_protocol_codes_and_never_supply_successful_trailers() {
    let body = StreamBody::new(stream::iter(vec![Err::<Frame<Bytes>, _>(
        h3x::ErrorCode::MessageError.stream("bad body"),
    )]));
    let (reader, worker) = BodyReader::bridge(body, OperationState::new());
    let task = tokio::spawn(worker);
    let error = reader.next().await.unwrap_err();
    assert_eq!(error.code, ErrorCode::Protocol);
    assert_eq!(
        error.protocol_code,
        Some(h3x::ErrorCode::MessageError.as_u64())
    );
    assert_eq!(
        reader.trailers().await.unwrap_err().code,
        ErrorCode::Protocol
    );
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn successful_receive_eof_does_not_cancel_a_pending_upload() {
    let state = OperationState::new();
    let (reader, worker) = BodyReader::bridge(Full::new(Bytes::new()), state.clone());
    let task = tokio::spawn(worker);
    assert!(reader.next().await.unwrap().is_none());
    drop(reader);
    assert!(task.await.unwrap().is_ok());
    assert!(!state.cancel.is_cancelled());
}
