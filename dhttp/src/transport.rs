//! Declaration-only adapter required by h3x's typed connection pool.
//! No stream forwarding, error mapping or transport behavior is implemented.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use h3x::{Role, Transport, TransportError};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct DquicTransport {
    connection: qconn::ArcConnection,
    role: Role,
}

pub(crate) struct RecvStream(qtransport::StreamReader);
pub(crate) struct SendStream(qtransport::StreamWriter);

impl Transport for DquicTransport {
    type StreamReader = RecvStream;
    type StreamWriter = SendStream;

    fn role(&self) -> Role {
        todo!("connection role")
    }

    async fn open_bi(&self) -> h3x::Result<Option<(u64, (RecvStream, SendStream))>> {
        todo!("open bidirectional QUIC stream")
    }

    async fn accept_bi(&self) -> h3x::Result<(u64, (RecvStream, SendStream))> {
        todo!("accept bidirectional QUIC stream")
    }

    async fn open_uni(&self) -> h3x::Result<Option<(u64, SendStream)>> {
        todo!("open unidirectional QUIC stream")
    }

    async fn accept_uni(&self) -> h3x::Result<(u64, RecvStream)> {
        todo!("accept unidirectional QUIC stream")
    }

    fn close(&self, reason: String, code: u64) -> h3x::Result<()> {
        todo!("close QUIC connection")
    }
}

impl TransportError for RecvStream {
    fn map_error(error: io::Error) -> h3x::Error {
        todo!("classify receive errors")
    }
}

impl TransportError for SendStream {
    fn map_error(error: io::Error) -> h3x::Error {
        todo!("classify send errors")
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        todo!("forward read")
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        todo!("forward write")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("forward flush")
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("finish send direction")
    }
}

impl StopSending for RecvStream {
    fn stop(&mut self, error_code: u64) {
        todo!("stop receive direction")
    }
}

impl CancelStream for SendStream {
    fn cancel(&mut self, error_code: u64) {
        todo!("cancel send direction")
    }
}
