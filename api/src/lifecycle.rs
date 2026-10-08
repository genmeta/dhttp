use crate::{Error, ErrorCode, Result};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, task_tracker::TaskTrackerToken},
};

#[derive(Clone)]
pub(crate) struct Scope(Arc<Inner>);

struct Inner {
    closed: Mutex<bool>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

pub(crate) struct Operation {
    // Reuse Tokio's task ownership accounting, including for native response Bodies.
    _tracked: TaskTrackerToken,
    pub state: Arc<OperationState>,
}

pub(crate) struct OperationState {
    pub cancel: CancellationToken,
    owner_cancel: Option<CancellationToken>,
    error: Mutex<Option<Error>>,
}

impl OperationState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel: CancellationToken::new(),
            owner_cancel: None,
            error: Mutex::new(None),
        })
    }

    fn owned_by(cancel: &CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            cancel: cancel.child_token(),
            owner_cancel: Some(cancel.clone()),
            error: Mutex::new(None),
        })
    }

    pub fn fail(&self, error: Error) {
        self.error.lock().unwrap().get_or_insert(error);
        self.cancel.cancel();
    }

    pub fn error(&self) -> Error {
        self.error.lock().unwrap().clone().unwrap_or_else(|| {
            if self
                .owner_cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                Error::new(ErrorCode::Closed, "SDK handle is closed")
            } else {
                Error::cancelled()
            }
        })
    }

    pub async fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(self.error()),
            result = future => result,
        }
    }
}

impl Scope {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            closed: Mutex::new(false),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }))
    }

    pub fn ensure_open(&self) -> Result<()> {
        if *self.0.closed.lock().unwrap() {
            Err(Error::new(ErrorCode::Closed, "SDK handle is closed"))
        } else {
            Ok(())
        }
    }

    pub fn register(&self) -> Result<Operation> {
        // Serialize registration with close: TaskTracker itself allows tokens
        // after close, whereas an SDK handle must reject new operations.
        let closed = self.0.closed.lock().unwrap();
        if *closed {
            return Err(Error::new(ErrorCode::Closed, "SDK handle is closed"));
        }
        Ok(Operation {
            _tracked: self.0.tasks.token(),
            state: OperationState::owned_by(&self.0.cancel),
        })
    }

    pub fn cancel(&self) {
        *self.0.closed.lock().unwrap() = true;
        self.0.cancel.cancel();
        self.0.tasks.close();
    }

    pub async fn close(&self) {
        self.cancel();
        self.0.tasks.wait().await;
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
