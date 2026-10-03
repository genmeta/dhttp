//! Adapter between an established qconn connection and h3x stream I/O.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
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

impl QuicTransport {
    pub(crate) fn new(
        connection: qconn::ArcConnection,
        local: Option<qtls::LocalAuthority>,
        remote: Option<qtls::RemoteAuthority>,
        role: Role,
    ) -> crate::Result<Self> {
        let connection = Arc::new(connection);
        if connection.alpn() != b"h3" {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "negotiated ALPN is not h3").into(),
            );
        }
        let handshake = Arc::new(qtls::HandshakeSummary {
            alpn: Some(Bytes::copy_from_slice(connection.alpn())),
            local,
            remote,
        });
        Ok(Self {
            connection,
            handshake,
            role,
        })
    }
}

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
        map_stream_error(error)
    }
}

impl TransportError for SendStream {
    fn map_error(error: io::Error) -> h3x::Error {
        map_stream_error(error)
    }
}

fn map_stream_error(error: io::Error) -> h3x::Error {
    if let Some(qtransport::StreamError::Reset(reset)) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<qtransport::StreamError>())
        && let Ok(code) = ErrorCode::try_from(reset.error_code())
    {
        return code.stream(error.to_string());
    }
    h3x::Error::from_stream_io(error)
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

#[cfg(test)]
mod tests {
    use super::*;
    use qbase::{
        ArcReceiving,
        param::{
            ArcParameters,
            handy::{client_parameters, server_parameters},
        },
        sid::handy::DemandConcurrency,
    };

    #[test]
    fn quic_stream_resets_preserve_the_http3_error_code() {
        for code in [
            ErrorCode::NoError,
            ErrorCode::RequestRejected,
            ErrorCode::RequestCancelled,
        ] {
            let reset = qtransport::StreamError::Reset(qbase::frame::ResetStreamError::new(
                qbase::varint::VarInt::try_from(code.as_u64()).unwrap(),
                0u32.into(),
            ));
            for error in [
                RecvStream::map_error(reset.clone().into()),
                SendStream::map_error(reset.clone().into()),
            ] {
                assert!(matches!(error, h3x::Error::Stream(_)));
                assert_eq!(error.code, code);
            }
        }
        let existing = ErrorCode::GeneralProtocolError.connection("connection failed");
        assert_eq!(RecvStream::map_error(existing.clone().into()), existing);
        assert_eq!(SendStream::map_error(existing.clone().into()), existing);
        let unknown = qtransport::StreamError::Reset(qbase::frame::ResetStreamError::new(
            0xffffu32.into(),
            0u32.into(),
        ));
        assert_eq!(
            SendStream::map_error(unknown.into()).code,
            ErrorCode::InternalError
        );
    }

    fn connection(alpn: &'static [u8]) -> (qconn::ArcConnection, ArcReceiving<qconn::CloseReason>) {
        let parameters = ArcParameters::new(
            qbase::role::Role::Client,
            Arc::new(client_parameters()),
            Arc::new(server_parameters()),
        );
        let streams = qconn::DataStreams::new(
            parameters,
            Box::new(DemandConcurrency),
            qconn::ArcReliableFrames::with_capacity(0),
            None,
        );
        let close = ArcReceiving::default();
        (
            qconn::ArcConnection::new(Bytes::from_static(alpn), streams, close.clone()),
            close,
        )
    }

    #[tokio::test]
    async fn invalid_alpn_releases_the_connection_and_notifies_its_driver() {
        for alpn in [b"".as_slice(), b"h2", b"h3-29"] {
            let (connection, close) = connection(alpn);
            let result = QuicTransport::new(connection, None, None, Role::Client);
            assert!(
                matches!(result, Err(crate::Error::Io { source }) if source.kind() == io::ErrorKind::InvalidData)
            );
            let reason = tokio::time::timeout(std::time::Duration::from_secs(1), close)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(matches!(reason, qconn::CloseReason::App(_)));
        }
    }

    #[tokio::test]
    async fn h3_transport_keeps_the_negotiated_protocol_and_role() {
        for role in [Role::Client, Role::Server] {
            let (connection, mut close) = connection(b"h3");
            let transport = QuicTransport::new(connection, None, None, role).unwrap();
            assert_eq!(transport.role(), role);
            assert_eq!(transport.handshake.alpn.as_deref(), Some(b"h3".as_slice()));
            assert!(futures::poll!(&mut close).is_pending());
            drop(transport);
            assert!(matches!(
                close.await.unwrap().unwrap(),
                qconn::CloseReason::App(_)
            ));
        }
    }
}
