use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
};

use bytes::Bytes;
use futures::stream;
use h3x::{ReadRequest, WriteResponse};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_service::Service;

use crate::transport::QuicTransport;
use crate::{ArcWndBuf, Body, BoxError, DhttpNetwork, Method, Request, Result, Scopes, Uri};

/// A named DHTTP participant. Clones share the same logical name instance.
/// Network resolves credentials and connections when this participant is used.
#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

impl Endpoint {
    /// Resolve and validate a named participant without owning transport state.
    /// Credential lookup for a new connection or listener belongs to Network.
    pub async fn load(servername: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: Arc::from(
                dhttp_home::normalize_name(servername.as_ref()).ok_or_else(|| {
                    crate::Error::InvalidName {
                        name: servername.as_ref().to_owned(),
                    }
                })?,
            ),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) async fn quic_endpoint(name: &str) -> Result<qconn::QuicEndpoint> {
        let identity = crate::home::load_identity(name).await?;
        let mut endpoint = qconn::QuicEndpoint::new(identity);
        endpoint.set_alpn(vec![h3x::ALPN.to_vec()]);
        Ok(endpoint)
    }

    pub(crate) async fn open_outbound(
        (local_name, remote_name): (Arc<str>, Arc<str>),
    ) -> Result<h3x::H3Connection<QuicTransport>> {
        let endpoint = Self { name: local_name };
        let quic = Self::quic_endpoint(endpoint.name()).await?;
        // TODO: qconn::connect still lacks path discovery and insertion; it
        // cannot finish the handshake until that lower-layer work is connected.
        let (local, remote, connection) =
            quic.connect(remote_name.to_string())
                .await
                .map_err(|source| crate::Error::Quic {
                    source: Arc::new(source),
                })?;
        let alpn = Bytes::copy_from_slice(connection.alpn());
        let connection = Arc::new(connection);
        let transport = QuicTransport {
            connection: connection.clone(),
            handshake: Arc::new(qtls::HandshakeSummary {
                alpn: Some(alpn),
                local,
                remote: Some(remote),
            }),
            role: h3x::Role::Client,
        };
        let h3 = h3x::H3Connection::new(transport, h3x::Settings::default()).map_err(|source| {
            (*connection)
                .clone()
                .close(qbase::varint::VarInt::from_u32(0), "HTTP/3 setup failed");
            crate::Error::Http3 {
                source: Arc::new(source),
            }
        })?;
        // TODO: Drive accept_bi on outbound connections too, then pass each
        // stream through h3x::ReadRequest and the Endpoint's listening Service.
        Ok(h3)
    }

    /// Construct an editable request with no caller-written body. The caller
    /// parses the URI before this call; network I/O begins when await is polled.
    pub fn get(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound GET request")
    }

    pub fn head(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound HEAD request")
    }

    pub fn delete(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound DELETE request")
    }

    pub fn options(&self, uri: Uri) -> Request<()> {
        todo!("construct an endpoint-bound OPTIONS request")
    }

    pub fn post(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound POST request")
    }

    pub fn put(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound PUT request")
    }

    pub fn patch(&self, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an endpoint-bound PATCH request")
    }

    pub fn request(&self, method: Method, uri: Uri) -> Request<ArcWndBuf> {
        todo!("construct an editable request for the specified method")
    }

    /// Register one application for the specified source scopes and drive it
    /// until stopped or an admission error. Network socket rules also apply.
    /// Same-endpoint duplicates fail with AlreadyListening; another active
    /// endpoint with the same normalized name fails with NameInUse.
    ///
    /// Service request extensions contain ArcConnection and HandshakeSummary
    /// from the actual accepted connection. Drive readiness and call on the
    /// same service instance. Body/trailers stay streaming.
    ///
    /// Cancelling listen cuts off admission and starts publication withdrawal.
    /// The caller owns all routing and application runtimes behind the Service.
    pub async fn listen<S, B>(&self, scopes: impl Into<Scopes>, app: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let network = DhttpNetwork::global()?;
        let (mut accepted, _registration) = network
            .accept_connections(self.name.clone(), scopes.into())
            .await?;
        let (stopping, _) = tokio::sync::watch::channel(false);
        let mut tasks = Vec::new();
        let mut shutdown_check = tokio::time::interval(std::time::Duration::from_millis(100));
        let had_sockets = !qprotocol::Dock::global().is_empty();
        loop {
            tokio::select! {
                _ = shutdown_check.tick() => {
                    // TODO: A dedicated shutdown signal would avoid polling Dock.
                    if had_sockets && qprotocol::Dock::global().is_empty() { break; }
                }
                incoming = accepted.recv() => match incoming {
                    Some(Ok(h3)) => {
                        let app = app.clone();
                        let local_name = self.name.clone();
                        let shutdown = stopping.subscribe();
                        let task = tokio::spawn(async move {
                            serve_connection(app, h3, network, local_name, shutdown).await;
                        });
                        tasks.retain(|handle: &tokio::task::JoinHandle<()>| !handle.is_finished());
                        tasks.push(task);
                    }
                    Some(Err(_)) => continue,
                    None => break,
                }
            }
        }
        stopping.send_replace(true);
        for task in tasks {
            let _ = task.await;
        }
        Ok(())
    }
}

async fn serve_connection<S, B>(
    app: S,
    h3: h3x::H3Connection<QuicTransport>,
    network: &'static DhttpNetwork,
    local_name: Arc<str>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    S: Service<http::Request<Body>, Response = http::Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let mut tasks = Vec::new();
    let mut cancelled = false;
    loop {
        if *shutdown.borrow() {
            cancelled = true;
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    cancelled = true;
                    break;
                }
            }
            incoming = h3.accept_bi() => match incoming {
                Ok((writer, reader)) => {
                    let app = app.clone();
                    let qpack = h3.qpack().clone();
                    let exchange_transport = h3.transport().clone();
                    let task = tokio::spawn(async move {
                        serve_exchange(app, writer, reader, qpack, exchange_transport).await;
                    });
                    tasks.retain(|handle: &tokio::task::JoinHandle<()>| !handle.is_finished());
                    tasks.push(task);
                }
                Err(_) => break,
            }
        }
    }
    for task in tasks {
        if cancelled {
            task.abort();
        }
        let _ = task.await;
    }
    network.forget_connection(&local_name, &h3);
    let _ = h3.close("listener stopped", 0);
}

async fn serve_exchange<S, B>(
    mut app: S,
    writer: h3x::H3WriteStream<crate::transport::SendStream>,
    reader: h3x::H3ReadStream<crate::transport::RecvStream>,
    qpack: h3x::ArcQpack,
    transport: QuicTransport,
) where
    S: Service<http::Request<Body>, Response = http::Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let Ok(incoming) = reader.read_request(qpack.clone()).await else {
        return;
    };
    let (mut parts, inbound) = incoming.into_parts();
    let method = parts.method.clone();
    let trailers = parts
        .extensions
        .remove::<h3x::Trailers>()
        .unwrap_or_default();
    parts.extensions.insert((*transport.connection).clone());
    parts.extensions.insert((*transport.handshake).clone());
    let stream = stream::unfold(
        (inbound, trailers, false),
        |(mut body, trailers, done)| async move {
            if done {
                return None;
            }
            let mut buffer = vec![0; 16 * 1024];
            match body.read(&mut buffer).await {
                Ok(0) => {
                    let fields = trailers.headers();
                    (!fields.is_empty())
                        .then_some((Ok(Frame::trailers(fields)), (body, trailers, true)))
                }
                Ok(size) => Some((
                    Ok(Frame::data(Bytes::from(buffer[..size].to_vec()))),
                    (body, trailers, false),
                )),
                Err(error) => Some((Err(Box::new(error) as BoxError), (body, trailers, true))),
            }
        },
    );
    let body: Body = StreamBody::new(stream).boxed_unsync();
    let request: http::Request<Body> = http::Request::from_parts(parts, body);
    if poll_fn(|cx| app.poll_ready(cx)).await.is_err() {
        return;
    }
    let response_future: Pin<
        Box<dyn Future<Output = std::result::Result<http::Response<B>, S::Error>> + Send>,
    > = Box::pin(app.call(request));
    let Ok(response) = response_future.await else {
        return;
    };
    let (parts, body) = response.into_parts();
    let mut buffer = ArcWndBuf::new(64 * 1024);
    let outgoing = h3x::Response::<h3x::W>::from_parts(parts, buffer.clone());
    let pump = outgoing.clone();
    let pumping = async move {
        let mut body = Box::pin(body);
        loop {
            let frame: Option<std::result::Result<Frame<Bytes>, BoxError>> =
                body.frame().await.map(|frame| frame.map_err(Into::into));
            let Some(frame) = frame else { break };
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => return Err(error),
            };
            match frame.into_data() {
                Ok(data) => {
                    buffer
                        .write_all(&data)
                        .await
                        .map_err(|error| Box::new(error) as BoxError)?;
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        for (name, value) in trailers {
                            if let Some(name) = name {
                                pump.append_trailer(name, value);
                            }
                        }
                    }
                }
            }
        }
        buffer
            .shutdown()
            .await
            .map_err(|error| Box::new(error) as BoxError)?;
        Ok::<(), BoxError>(())
    };
    let writing = writer.write_response(outgoing, method, qpack);
    tokio::pin!(pumping, writing);
    tokio::select! {
        result = &mut writing => {
            if result.is_ok() { let _ = pumping.await; }
        }
        result = &mut pumping => {
            if result.is_ok() { let _ = writing.await; }
        }
    }
}
