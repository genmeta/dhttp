fn receiving_body(
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

fn send_response<B, W>(
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
