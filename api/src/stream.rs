use crate::{Error, ErrorCode, Result, lifecycle::OperationState};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::HeaderMap;
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{Mutex, mpsc, oneshot, watch};

const CHUNK_BYTES: usize = 16 * 1024;
const QUEUED_CHUNKS: usize = 4;

enum UploadFrame {
    Data(Bytes),
    Finish(HeaderMap),
}

/// Finite upload bridge: at most four 16 KiB chunks await native consumption.
/// Dropping the writer without finish is an error, not successful EOF.
pub fn upload_channel() -> (UploadWriter, UploadBody) {
    let (sender, receiver) = mpsc::channel(QUEUED_CHUNKS);
    let state = OperationState::new();
    let cancelled = Box::pin(state.cancel.clone().cancelled_owned());
    (
        UploadWriter {
            sender: Mutex::new(Some(sender)),
            state: state.clone(),
        },
        UploadBody {
            receiver,
            state,
            cancelled,
            ended: false,
        },
    )
}

pub struct UploadWriter {
    sender: Mutex<Option<mpsc::Sender<UploadFrame>>>,
    state: Arc<OperationState>,
}

struct CancelWriteOnDrop(Option<Arc<OperationState>>);
impl Drop for CancelWriteOnDrop {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.fail(Error::cancelled());
        }
    }
}

impl UploadWriter {
    /// Splits large producer chunks before enqueueing, preserving backpressure.
    /// Cancellation while writing fails the entire upload rather than losing bytes.
    pub async fn send(&self, bytes: impl AsRef<[u8]>) -> Result<()> {
        let mut guard = CancelWriteOnDrop(Some(self.state.clone()));
        let result = self
            .state
            .run(async {
                let lock = self.sender.lock().await;
                let sender = lock
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::Closed, "upload finished"))?;
                for chunk in bytes.as_ref().chunks(CHUNK_BYTES) {
                    let permit = sender
                        .reserve()
                        .await
                        .map_err(|_| Error::new(ErrorCode::Closed, "upload consumer closed"))?;
                    permit.send(UploadFrame::Data(Bytes::copy_from_slice(chunk)));
                }
                Ok(())
            })
            .await;
        guard.0 = None;
        result
    }

    /// Freeze trailers and publish EOF after all previously enqueued bytes.
    pub async fn finish(&self, trailers: HeaderMap) -> Result<()> {
        let mut guard = CancelWriteOnDrop(Some(self.state.clone()));
        let result = self
            .state
            .run(async {
                let mut lock = self.sender.lock().await;
                let sender = lock
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::Closed, "upload finished"))?;
                sender
                    .send(UploadFrame::Finish(trailers))
                    .await
                    .map_err(|_| Error::new(ErrorCode::Closed, "upload consumer closed"))?;
                *lock = None;
                Ok(())
            })
            .await;
        guard.0 = None;
        result
    }

    pub fn fail(&self, error: Error) {
        self.state.fail(error);
    }

    /// Notify language producers when the native consumer has released its body.
    pub async fn closed(&self) {
        let sender = self.sender.lock().await.as_ref().cloned();
        if let Some(sender) = sender {
            sender.closed().await;
        }
    }
}

pub struct UploadBody {
    receiver: mpsc::Receiver<UploadFrame>,
    state: Arc<OperationState>,
    cancelled: BoxFuture<'static, ()>,
    ended: bool,
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        if this.cancelled.as_mut().poll(cx).is_ready() {
            this.ended = true;
            this.receiver.close();
            return Poll::Ready(Some(Err(this.state.error())));
        }
        match this.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(UploadFrame::Data(bytes))) => {
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(UploadFrame::Finish(trailers))) => {
                this.ended = true;
                this.receiver.close();
                if trailers.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
            }
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(Some(Err(Error::new(
                    ErrorCode::Producer,
                    "upload writer dropped before finish",
                ))))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.ended
    }
}

type ReadReply = oneshot::Sender<Result<Option<Bytes>>>;
type Completion = Option<Result<HeaderMap>>;

/// Demand-driven receive handle. No DATA is polled until `next()` requests it.
/// Only one `next()` may be active. Drop/cancel also releases the native Body.
pub struct BodyReader {
    commands: mpsc::Sender<ReadReply>,
    completion: watch::Receiver<Completion>,
    state: Arc<OperationState>,
    reading: Mutex<()>,
}

impl BodyReader {
    pub(crate) fn bridge<B>(
        body: B,
        state: Arc<OperationState>,
    ) -> (Self, BoxFuture<'static, Result<()>>)
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<dhttp::BoxError>,
    {
        let (commands, mut receive) = mpsc::channel::<ReadReply>(1);
        let (complete, completion) = watch::channel(None);
        let worker_state = state.clone();
        let worker = Box::pin(async move {
            let mut body = body;
            let result = worker_state
                .run(async {
                    let mut trailers = HeaderMap::new();
                    while let Some(reply) = receive.recv().await {
                        let next = loop {
                            match body.frame().await {
                                None => break None,
                                Some(Err(error)) => {
                                    let cause: dhttp::BoxError = error.into();
                                    let error = Error::from(cause);
                                    let _ = reply.send(Err(error.clone()));
                                    return Err(error);
                                }
                                Some(Ok(frame)) => match frame.into_data() {
                                    Ok(data) => break Some(data),
                                    Err(frame) => {
                                        if let Ok(fields) = frame.into_trailers() {
                                            // append preserves duplicate fields across all frames.
                                            for (name, value) in fields.iter() {
                                                trailers.append(name.clone(), value.clone());
                                            }
                                        }
                                    }
                                },
                            }
                        };
                        let ended = next.is_none();
                        if ended {
                            // Publish completion before waking the consumer. On a
                            // multithreaded runtime it may drop the reader as soon
                            // as it sees EOF; that must not cancel a live upload.
                            complete.send_replace(Some(Ok(std::mem::take(&mut trailers))));
                        }
                        if reply.send(Ok(next)).is_err() {
                            return Err(Error::cancelled());
                        }
                        if ended {
                            return Ok(());
                        }
                    }
                    Err(Error::cancelled())
                })
                .await;
            if let Err(error) = &result {
                worker_state.fail(error.clone());
                complete.send_replace(Some(Err(error.clone())));
            }
            result
        });
        (
            Self {
                commands,
                completion,
                state,
                reading: Mutex::new(()),
            },
            worker,
        )
    }

    pub async fn next(&self) -> Result<Option<Bytes>> {
        let _reading = self
            .reading
            .try_lock()
            .map_err(|_| Error::new(ErrorCode::BodyInUse, "body already has a reader"))?;
        if let Some(result) = self.completion.borrow().clone() {
            return result.map(|_| None);
        }
        let (reply, response) = oneshot::channel();
        let mut guard = CancelWriteOnDrop(Some(self.state.clone()));
        let result = self
            .state
            .run(async {
                self.commands
                    .send(reply)
                    .await
                    .map_err(|_| self.state.error())?;
                response.await.map_err(|_| self.state.error())?
            })
            .await;
        guard.0 = None;
        result
    }

    /// Available after successful EOF. Does not implicitly consume body DATA.
    pub async fn trailers(&self) -> Result<HeaderMap> {
        let mut completion = self.completion.clone();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result;
            }
            self.state
                .run(async { completion.changed().await.map_err(|_| self.state.error()) })
                .await?;
        }
    }

    #[cfg(any(feature = "napi", feature = "pyo3"))]
    pub(crate) async fn closed(&self) {
        self.state.cancel.cancelled().await;
    }

    pub fn cancel(&self) {
        self.state.fail(Error::cancelled());
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        // Successful receive EOF does not cancel an upload still completing.
        if !matches!(*self.completion.borrow(), Some(Ok(_))) {
            self.cancel();
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/receive.rs"]
mod tests;
