//! Adapter between an established qconn connection and h3x stream I/O.
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use h3x::{ErrorCode, Role, Transport, TransportError};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub(crate) struct QuicTransport {
    pub(crate) connection: Arc<qconn::ArcConnection>,
    pub(crate) handshake: Arc<qtls::HandshakeSummary>,
    pub(crate) role: Role,
}

pub(crate) struct RecvStream(qtransport::StreamReader);
pub(crate) struct SendStream(qtransport::StreamWriter);

impl Transport for QuicTransport {
    type StreamReader = RecvStream;
    type StreamWriter = SendStream;

    fn role(&self) -> Role {
        self.role
    }

    async fn open_bi(&self) -> h3x::Result<Option<(u64, (RecvStream, SendStream))>> {
        self.connection
            .open_bi_stream()
            .await
            .map(|stream| {
                stream.map(|(id, (recv, send))| (id.into(), (RecvStream(recv), SendStream(send))))
            })
            .map_err(|error| ErrorCode::InternalError.connection(error.to_string()))
    }

    async fn accept_bi(&self) -> h3x::Result<(u64, (RecvStream, SendStream))> {
        self.connection
            .accept_bi_stream()
            .await
            .map(|(id, (recv, send))| (id.into(), (RecvStream(recv), SendStream(send))))
            .map_err(|error| ErrorCode::InternalError.connection(error.to_string()))
    }

    async fn open_uni(&self) -> h3x::Result<Option<(u64, SendStream)>> {
        self.connection
            .open_uni_stream()
            .await
            .map(|stream| stream.map(|(id, send)| (id.into(), SendStream(send))))
            .map_err(|error| ErrorCode::InternalError.connection(error.to_string()))
    }

    async fn accept_uni(&self) -> h3x::Result<(u64, RecvStream)> {
        self.connection
            .accept_uni_stream()
            .await
            .map(|(id, recv)| (id.into(), RecvStream(recv)))
            .map_err(|error| ErrorCode::InternalError.connection(error.to_string()))
    }

    fn close(&self, reason: String, code: u64) -> h3x::Result<()> {
        let code = qbase::varint::VarInt::try_from(code)
            .map_err(|error| ErrorCode::InternalError.connection(error.to_string()))?;
        (*self.connection).clone().close(code, &reason);
        Ok(())
    }
}

impl TransportError for RecvStream {
    fn map_error(error: io::Error) -> h3x::Error {
        h3x::Error::from_stream_io(error)
    }
}

impl TransportError for SendStream {
    fn map_error(error: io::Error) -> h3x::Error {
        h3x::Error::from_stream_io(error)
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl StopSending for RecvStream {
    fn stop(&mut self, error_code: u64) {
        self.0.stop(error_code)
    }
}

impl CancelStream for SendStream {
    fn cancel(&mut self, error_code: u64) {
        self.0.cancel(error_code)
    }
}
