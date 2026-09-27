use super::*;
impl<B> Request<B> {
    pub fn header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().insert(name, value);
        self
    }

    pub fn append_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.message.headers_mut().append(name, value);
        self
    }

    pub fn body<T>(self, body: T) -> Request<T> {
        let (parts, _) = self.message.into_parts();
        Request {
            endpoint: self.endpoint,
            message: http::Request::from_parts(parts, body),
        }
    }
}

impl<B> IntoFuture for Request<B>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Output = Result<http::Response<Body>>;
    type IntoFuture = RequestFuture;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let network = DhttpNetwork::global()?;
            let mut message = self.message;
            *message.uri_mut() = canonical_uri(&self.endpoint, message.uri())?;
            let remote = remote_name(message.uri())?;
            let h3 = network
                .get_connection(self.endpoint.name.clone(), remote)
                .await?;
            let (writer, reader) = tokio::time::timeout(OPERATION_TIMEOUT, h3.open_bi())
                .await
                .map_err(io_error)?
                .map_err(h3_error)?;
            send_request(message, writer, reader, h3.qpack().clone()).await
        })
    }
}

pub(super) fn canonical_uri(endpoint: &Endpoint, uri: &http::Uri) -> Result<http::Uri> {
    let name =
        dhttp_identity::name::DhttpName::try_from(endpoint.name().to_owned()).map_err(|error| {
            Error::InvalidRequest {
                message: error.to_string(),
            }
        })?;
    name.expand_uri(uri.clone())
        .map_err(|error| Error::InvalidRequest {
            message: error.to_string(),
        })
}

pub(super) fn remote_name(uri: &http::Uri) -> Result<Arc<str>> {
    if let Some(scheme) = uri.scheme_str()
        && !matches!(scheme, "https" | "http" | "dhttp" | "wss" | "ws")
    {
        return Err(Error::InvalidRequest {
            message: "unsupported URI scheme".into(),
        });
    }
    let host = uri.host().ok_or_else(|| Error::InvalidRequest {
        message: "URI has no remote authority".into(),
    })?;
    dhttp_home::normalize_name(host)
        .map(Arc::from)
        .ok_or_else(|| Error::InvalidName { name: host.into() })
}

pub(super) async fn send_request<B, W, R>(
    message: http::Request<B>,
    writer: W,
    reader: R,
    qpack: h3x::ArcQpack,
) -> Result<http::Response<Body>>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    W: WriteRequest + CancelStream + 'static,
    R: ReadResponse,
{
    let method = message.method().clone();
    let (mut parts, body) = message.into_parts();
    // Forwarded trusted identities never affect this endpoint's outbound authentication.
    parts.extensions.remove::<qtls::HandshakeSummary>();
    parts.extensions.remove::<qtls::LocalAuthority>();
    parts.extensions.remove::<qtls::RemoteAuthority>();
    let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
    let outgoing = h3x::Request::<h3x::W>::from_parts(parts, buffer.clone());
    let response_cancel = outgoing.clone();
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    let send_qpack = qpack.clone();
    let upload = tokio::spawn(async move {
        let trailers = outgoing.clone();
        let writing =
            scopeguard::ScopeGuard::into_inner(writer).write_request(outgoing, send_qpack);
        tokio::pin!(writing);
        let guard = scopeguard::guard(trailers.clone(), |mut request| {
            request.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
        });
        let pumping = pump_body(body, buffer, move |name, value| {
            trailers.append_trailer(name, value);
        });
        tokio::try_join!(biased; async { (&mut writing).await.map_err(h3_error) }, pumping)?;
        scopeguard::ScopeGuard::into_inner(guard);
        Ok(())
    });
    let mut upload = scopeguard::guard(upload, |task| task.abort());
    let reading = reader.read_response(method, qpack);
    tokio::pin!(reading);
    let response_cancel = scopeguard::guard(response_cancel, |mut request| {
        request.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
    });
    let timeout = tokio::time::timeout(OPERATION_TIMEOUT, &mut reading);
    tokio::pin!(timeout);
    // A completed upload is not a prerequisite for returning response headers.
    let mut completed = false;
    let response = loop {
        tokio::select! {
            result = &mut *upload, if !completed => { upload_result(result.map_err(io_error)?)?; completed = true; },
            response = &mut timeout => break response.map_err(io_error)?.map_err(h3_error)?,
        }
    };
    let (mut parts, inbound) = response.into_parts();
    let trailers = parts
        .extensions
        .remove::<h3x::Trailers>()
        .unwrap_or_default();
    let native = scopeguard::guard(inbound, |mut body| {
        body.stop(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    let stream = async_stream::try_stream! {
        let mut native = native;
        let mut upload = upload;
        loop {
            let mut bytes = vec![0; BODY_READ_CHUNK_BYTES];
            let count = async {
                let reading = tokio::time::timeout(OPERATION_TIMEOUT, native.read(&mut bytes));
                tokio::pin!(reading);
                loop {
                    tokio::select! {
                        result = &mut *upload, if !completed => { upload_result(result.map_err(io_error)?)?; completed = true; },
                        result = &mut reading => return result.map_err(io_error)?.map_err(io_error),
                    }
                }
            }.await?;
            if count == 0 { break; }
            bytes.truncate(count);
            yield Frame::data(Bytes::from(bytes));
        }
        scopeguard::ScopeGuard::into_inner(native);
        // EOF completes receiving. Upload may continue independently until its own EOF.
        scopeguard::ScopeGuard::into_inner(upload);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    };
    let body = StreamBody::new(stream)
        .map_err(|error: Error| Box::new(error) as BoxError)
        .boxed_unsync();
    scopeguard::ScopeGuard::into_inner(response_cancel);
    Ok(http::Response::from_parts(parts, body))
}

// A server may decline further upload with H3_NO_ERROR while still returning
// a valid response. Both the native writer and the body pump can observe it.
fn upload_result(result: Result<()>) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if cause
            .downcast_ref::<h3x::Error>()
            .is_some_and(|error| error.code == h3x::ErrorCode::NoError)
        {
            return Ok(());
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
        {
            cause = inner;
            continue;
        }
        match cause.source() {
            Some(source) => cause = source,
            None => break,
        }
    }
    Err(error)
}

pub(super) fn receiving_body(
    inbound: h3x::ArcWndBuf,
    trailers: h3x::Trailers,
    drop_code: h3x::ErrorCode,
) -> Body {
    // Construct before the generator: dropping an entirely unpolled Body must stop native input too.
    let guard = scopeguard::guard(inbound, move |mut body| body.stop(drop_code.as_u64()));
    StreamBody::new(async_stream::try_stream! {
        let mut guard = guard;
        loop {
            let mut bytes = vec![0; BODY_READ_CHUNK_BYTES];
            let count = tokio::time::timeout(OPERATION_TIMEOUT, guard.read(&mut bytes)).await.map_err(io_error)?.map_err(io_error)?;
            if count == 0 { break; }
            bytes.truncate(count);
            yield Frame::data(Bytes::from(bytes));
        }
        scopeguard::ScopeGuard::into_inner(guard);
        let fields = trailers.headers();
        if !fields.is_empty() { yield Frame::trailers(fields); }
    }).map_err(|error: Error| Box::new(error) as BoxError).boxed_unsync()
}

async fn pump_body<B>(
    body: B,
    mut native: h3x::ArcWndBuf,
    mut trailer: impl FnMut(http::HeaderName, http::HeaderValue),
) -> Result<()>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let mut body = Box::pin(body);
    loop {
        let frame: Option<std::result::Result<Frame<Bytes>, BoxError>> =
            tokio::time::timeout(OPERATION_TIMEOUT, body.frame())
                .await
                .map_err(io_error)?
                .map(|frame| frame.map_err(Into::into));
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(box_error)?;
        match frame.into_data() {
            Ok(data) => {
                tokio::time::timeout(OPERATION_TIMEOUT, native.write_bytes(data))
                    .await
                    .map_err(io_error)?
                    .map_err(io_error)?;
            }
            Err(frame) => {
                if let Ok(fields) = frame.into_trailers() {
                    // HeaderMap's borrowed iterator emits the name for every value.
                    for (name, value) in fields.iter() {
                        trailer(name.clone(), value.clone());
                    }
                }
            }
        }
    }
    native.shutdown().await.map_err(io_error)
}

pub(super) fn send_response<B, W>(
    response: http::Response<B>,
    method: http::Method,
    writer: W,
    qpack: h3x::ArcQpack,
) -> impl std::future::Future<Output = Result<()>>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
    W: WriteResponse + CancelStream,
{
    let writer = scopeguard::guard(writer, |mut writer| {
        writer.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
    });
    async move {
        let (parts, body) = response.into_parts();
        let suppressed = method == http::Method::HEAD
            || parts.status == http::StatusCode::NO_CONTENT
            || parts.status == http::StatusCode::NOT_MODIFIED;
        let body = if suppressed {
            drop(body);
            None
        } else {
            Some(body)
        };
        let buffer = h3x::ArcWndBuf::new(BODY_WINDOW_BYTES);
        let outgoing = h3x::Response::<h3x::W>::from_parts(parts, buffer.clone());
        let trailers = outgoing.clone();
        let writing =
            scopeguard::ScopeGuard::into_inner(writer).write_response(outgoing, method, qpack);
        tokio::pin!(writing);
        // This guard is declared after the pinned writer and therefore cancels
        // the native body before dropping the writer future on any exit.
        let guard = scopeguard::guard(trailers.clone(), |mut response| {
            response.cancel(h3x::ErrorCode::RequestCancelled.as_u64())
        });
        if let Some(body) = body {
            let pumping = pump_body(body, buffer, move |name, value| {
                trailers.append_trailer(name, value);
            });
            // Poll the writer first so its existing body cancellation callback
            // is installed before a producer can fail on its first frame.
            tokio::try_join!(biased; async { (&mut writing).await.map_err(h3_error) }, pumping)?;
        } else {
            writing.await.map_err(h3_error)?;
        }
        scopeguard::ScopeGuard::into_inner(guard);
        Ok(())
    }
}
