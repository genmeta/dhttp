//! Language-neutral asynchronous bridge for the Node and Python SDKs.
//!
//! N-API and PyO3 reuse the same streaming and cancellation ownership.
//! Native SDK discovery currently supports System DNS and explicit peers.
#![doc = include_str!("../README.md")]
#[cfg(any(feature = "napi", feature = "pyo3"))]
mod binding;
mod client;
mod error;
mod lifecycle;
#[cfg(feature = "napi")]
pub mod napi;
#[cfg(feature = "pyo3")]
mod python;
mod server;
mod stream;

pub use client::{Cancellation, Client, ClientResponse, RequestOptions, ResponseFuture};
pub use dhttp::{HandshakeSummary, HeaderMap, LocalAuthority, RemoteAuthority, Scopes};
pub use error::{Error, ErrorCode, Result};
pub use server::{Listener, ServerRequest, ServerResponse};
pub use stream::{BodyReader, UploadBody, UploadWriter, upload_channel};

/// Initialize the shared network. The embedding Tokio runtime must stay alive.
/// This currently leaves name discovery configuration to the caller.
pub async fn init() -> Result<()> {
    dhttp::DhttpNetwork::init()
        .await
        .map(|_| ())
        .map_err(Into::into)
}
