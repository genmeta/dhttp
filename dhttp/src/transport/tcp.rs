//! A test transport that multiplexes h3x streams over one loopback TCP socket.
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use h3x::{ErrorCode, Role, Transport, TransportError};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, mpsc, watch},
};

const STREAM_CAPACITY: usize = 64 * 1024;
const FRAME_CAPACITY: usize = 16 * 1024;
type BiStream = (u64, (TcpReader, TcpWriter));
type UniStream = (u64, TcpReader);

enum WireFrame {
    OpenBi(u64),
    OpenUni(u64),
    Data(u64, Bytes),
    Fin(u64),
    Close,
}

pub(crate) struct TcpTransport {
    pub(crate) handshake: Arc<qtls::HandshakeSummary>,
    role: Role,
    next_bi: AtomicU64,
    next_uni: AtomicU64,
    outgoing: mpsc::Sender<WireFrame>,
    register: mpsc::UnboundedSender<(u64, DuplexStream)>,
    incoming_bi: Mutex<mpsc::UnboundedReceiver<BiStream>>,
    incoming_uni: Mutex<mpsc::UnboundedReceiver<UniStream>>,
    closed: watch::Sender<bool>,
}

pub(crate) struct TcpReader {
    io: Option<DuplexStream>,
}

pub(crate) struct TcpWriter {
    io: Option<DuplexStream>,
}

impl TcpTransport {
    pub(crate) fn new(
        socket: TcpStream,
        role: Role,
        handshake: Arc<qtls::HandshakeSummary>,
    ) -> Self {
        let (reader, writer) = socket.into_split();
        let (outgoing, writes) = mpsc::channel(16);
        let (register, registrations) = mpsc::unbounded_channel();
        let (frames, wire) = mpsc::channel(16);
        let (incoming_bi, bi) = mpsc::unbounded_channel();
        let (incoming_uni, uni) = mpsc::unbounded_channel();
        let (closed, _) = watch::channel(false);
        tokio::spawn(write_wire(writer, writes, closed.clone()));
        tokio::spawn(read_wire(reader, frames, closed.clone()));
        tokio::spawn(dispatch(
            wire,
            registrations,
            incoming_bi,
            incoming_uni,
            outgoing.clone(),
        ));
        let (next_bi, next_uni) = match role {
            Role::Client => (0, 2),
            Role::Server => (1, 3),
        };
        Self {
            handshake,
            role,
            next_bi: AtomicU64::new(next_bi),
            next_uni: AtomicU64::new(next_uni),
            outgoing,
            register,
            incoming_bi: Mutex::new(bi),
            incoming_uni: Mutex::new(uni),
            closed,
        }
    }
}

fn transport_error(message: impl Into<String>) -> h3x::Error {
    ErrorCode::InternalError.connection(message.into())
}

async fn write_wire(
    mut writer: OwnedWriteHalf,
    mut frames: mpsc::Receiver<WireFrame>,
    closed: watch::Sender<bool>,
) {
    let mut stopping = closed.subscribe();
    loop {
        let frame = tokio::select! {
            _ = stopping.changed() => break,
            frame = frames.recv() => match frame { Some(frame) => frame, None => break },
        };
        let (kind, id, data): (u8, u64, &[u8]) = match &frame {
            WireFrame::OpenBi(id) => (1, *id, &[]),
            WireFrame::OpenUni(id) => (2, *id, &[]),
            WireFrame::Data(id, data) => (3, *id, data),
            WireFrame::Fin(id) => (4, *id, &[]),
            WireFrame::Close => (6, 0, &[]),
        };
        let mut header = [0_u8; 13];
        header[0] = kind;
        header[1..9].copy_from_slice(&id.to_be_bytes());
        header[9..13].copy_from_slice(&(data.len() as u32).to_be_bytes());
        if writer.write_all(&header).await.is_err() || writer.write_all(data).await.is_err() {
            break;
        }
        if matches!(frame, WireFrame::Close) {
            break;
        }
    }
    closed.send_replace(true);
}

async fn read_wire(
    mut reader: OwnedReadHalf,
    frames: mpsc::Sender<WireFrame>,
    closed: watch::Sender<bool>,
) {
    loop {
        let mut header = [0_u8; 13];
        if reader.read_exact(&mut header).await.is_err() {
            break;
        }
        let id = u64::from_be_bytes(header[1..9].try_into().unwrap());
        let length = u32::from_be_bytes(header[9..13].try_into().unwrap()) as usize;
        if length > FRAME_CAPACITY || (header[0] != 3 && length != 0) {
            break;
        }
        let frame = match header[0] {
            1 => WireFrame::OpenBi(id),
            2 => WireFrame::OpenUni(id),
            3 => {
                let mut bytes = vec![0; length];
                if reader.read_exact(&mut bytes).await.is_err() {
                    break;
                }
                WireFrame::Data(id, bytes.into())
            }
            4 => WireFrame::Fin(id),
            6 => WireFrame::Close,
            _ => break,
        };
        let last = matches!(frame, WireFrame::Close);
        if frames.send(frame).await.is_err() || last {
            break;
        }
    }
    closed.send_replace(true);
}

async fn pump(mut reader: DuplexStream, id: u64, outgoing: mpsc::Sender<WireFrame>) {
    let mut chunk = [0_u8; FRAME_CAPACITY];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => {
                let _ = outgoing.send(WireFrame::Fin(id)).await;
                break;
            }
            Ok(count) => {
                if outgoing
                    .send(WireFrame::Data(id, Bytes::copy_from_slice(&chunk[..count])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

async fn dispatch(
    mut frames: mpsc::Receiver<WireFrame>,
    mut registrations: mpsc::UnboundedReceiver<(u64, DuplexStream)>,
    incoming_bi: mpsc::UnboundedSender<BiStream>,
    incoming_uni: mpsc::UnboundedSender<UniStream>,
    outgoing: mpsc::Sender<WireFrame>,
) {
    let mut receivers = HashMap::<u64, DuplexStream>::new();
    loop {
        let frame = tokio::select! {
            biased;
            registration = registrations.recv(), if !registrations.is_closed() => {
                if let Some((id, writer)) = registration {
                    receivers.insert(id, writer);
                }
                continue;
            }
            frame = frames.recv() => match frame { Some(frame) => frame, None => break },
        };
        match frame {
            WireFrame::OpenBi(id) => {
                let (reader, inbound) = duplex(STREAM_CAPACITY);
                let (outbound, writer) = duplex(STREAM_CAPACITY);
                receivers.insert(id, inbound);
                tokio::spawn(pump(outbound, id, outgoing.clone()));
                let _ = incoming_bi.send((
                    id,
                    (
                        TcpReader { io: Some(reader) },
                        TcpWriter { io: Some(writer) },
                    ),
                ));
            }
            WireFrame::OpenUni(id) => {
                let (reader, inbound) = duplex(STREAM_CAPACITY);
                receivers.insert(id, inbound);
                let _ = incoming_uni.send((id, TcpReader { io: Some(reader) }));
            }
            WireFrame::Data(id, data) => {
                if let Some(writer) = receivers.get_mut(&id)
                    && writer.write_all(&data).await.is_err()
                {
                    receivers.remove(&id);
                }
            }
            WireFrame::Fin(id) => {
                receivers.remove(&id);
            }
            WireFrame::Close => break,
        }
    }
}

impl Transport for TcpTransport {
    type StreamReader = TcpReader;
    type StreamWriter = TcpWriter;

    fn role(&self) -> Role {
        self.role
    }

    async fn open_bi(&self) -> h3x::Result<Option<BiStream>> {
        if *self.closed.borrow() {
            return Ok(None);
        }
        let id = self.next_bi.fetch_add(4, Ordering::Relaxed);
        let (reader, inbound) = duplex(STREAM_CAPACITY);
        let (outbound, writer) = duplex(STREAM_CAPACITY);
        self.register
            .send((id, inbound))
            .map_err(|_| transport_error("TCP mock receiver stopped"))?;
        self.outgoing
            .send(WireFrame::OpenBi(id))
            .await
            .map_err(|_| transport_error("TCP mock writer stopped"))?;
        tokio::spawn(pump(outbound, id, self.outgoing.clone()));
        Ok(Some((
            id,
            (
                TcpReader { io: Some(reader) },
                TcpWriter { io: Some(writer) },
            ),
        )))
    }

    async fn accept_bi(&self) -> h3x::Result<BiStream> {
        let mut closed = self.closed.subscribe();
        let mut incoming = self.incoming_bi.lock().await;
        loop {
            if *closed.borrow() {
                return Err(transport_error("TCP mock connection closed"));
            }
            tokio::select! {
                _ = closed.changed() => {},
                stream = incoming.recv() => {
                    return stream.ok_or_else(|| transport_error("bidirectional stream queue closed"));
                }
            }
        }
    }

    async fn open_uni(&self) -> h3x::Result<Option<(u64, TcpWriter)>> {
        if *self.closed.borrow() {
            return Ok(None);
        }
        let id = self.next_uni.fetch_add(4, Ordering::Relaxed);
        let (outbound, writer) = duplex(STREAM_CAPACITY);
        self.outgoing
            .send(WireFrame::OpenUni(id))
            .await
            .map_err(|_| transport_error("TCP mock writer stopped"))?;
        tokio::spawn(pump(outbound, id, self.outgoing.clone()));
        Ok(Some((id, TcpWriter { io: Some(writer) })))
    }

    async fn accept_uni(&self) -> h3x::Result<(u64, TcpReader)> {
        let mut closed = self.closed.subscribe();
        let mut incoming = self.incoming_uni.lock().await;
        loop {
            if *closed.borrow() {
                return Err(transport_error("TCP mock connection closed"));
            }
            tokio::select! {
                _ = closed.changed() => {},
                stream = incoming.recv() => {
                    return stream.ok_or_else(|| transport_error("unidirectional stream queue closed"));
                }
            }
        }
    }

    fn close(&self, _: String, _: u64) -> h3x::Result<()> {
        self.closed.send_replace(true);
        let _ = self.outgoing.try_send(WireFrame::Close);
        Ok(())
    }
}

impl TransportError for TcpReader {
    fn map_error(error: io::Error) -> h3x::Error {
        h3x::Error::from_stream_io(error)
    }
}
impl TransportError for TcpWriter {
    fn map_error(error: io::Error) -> h3x::Error {
        h3x::Error::from_stream_io(error)
    }
}

impl AsyncRead for TcpReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.io.as_mut() {
            Some(reader) => Pin::new(reader).poll_read(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into())),
        }
    }
}

impl AsyncWrite for TcpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.io.as_mut() {
            Some(writer) => Pin::new(writer).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.io.as_mut() {
            Some(writer) => Pin::new(writer).poll_flush(cx),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.io.as_mut() {
            Some(writer) => Pin::new(writer).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl StopSending for TcpReader {
    fn stop(&mut self, _: u64) {
        self.io.take();
        // Reset targets the peer's receive half. A bidirectional stream may
        // still need that half to deliver its response after input is declined.
    }
}
impl CancelStream for TcpWriter {
    fn cancel(&mut self, _: u64) {
        self.io.take();
    }
}
