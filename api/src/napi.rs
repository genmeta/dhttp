use crate::{Error, ErrorCode, binding as b};
use ::napi::{
    Error as NError, Result as NResult,
    bindgen_prelude::{Buffer, Either, FnArgs, Function, Promise},
};
use napi_derive::napi;
use std::sync::Arc;

type Result<T> = NResult<T>;
fn err(error: Error) -> NError {
    NError::from_reason(serde_json::json!({"dhttp":true,"code":error.code.as_str(),"message":error.message,"protocolCode":error.protocol_code}).to_string())
}
fn callback_error(error: NError) -> Error {
    Error::new(ErrorCode::Producer, error.reason)
}

#[napi(object)]
pub struct Header {
    pub name: String,
    pub value: Buffer,
}
fn fields(headers: Vec<Header>) -> b::Fields {
    headers
        .into_iter()
        .map(|h| (h.name, h.value.to_vec()))
        .collect()
}
fn headers(fields: b::Fields) -> Vec<Header> {
    fields
        .into_iter()
        .map(|(name, value)| Header {
            name,
            value: value.into(),
        })
        .collect()
}

#[napi(object)]
pub struct Authority {
    pub name: String,
    pub certificates: Vec<Buffer>,
    pub public_key: Buffer,
    pub owner_hash: String,
    pub subject_key_identifier: Buffer,
}
impl From<b::Authority> for Authority {
    fn from(a: b::Authority) -> Self {
        Self {
            name: a.name,
            certificates: a.certificates.into_iter().map(Into::into).collect(),
            public_key: a.public_key.into(),
            owner_hash: a.owner_hash,
            subject_key_identifier: a.subject_key_identifier.into(),
        }
    }
}

#[napi]
pub async fn init(peers: Vec<Vec<String>>, root_certificates: Option<Buffer>) -> Result<()> {
    let peers = peers
        .into_iter()
        .map(|pair| match pair.as_slice() {
            [name, address] => Ok((name.clone(), address.clone())),
            _ => Err(b::invalid("peer must be [name, address]")),
        })
        .collect::<crate::Result<_>>()
        .map_err(err)?;
    b::init(peers, root_certificates.map(|bytes| bytes.to_vec()))
        .await
        .map_err(err)
}
#[napi]
pub fn addresses() -> Vec<String> {
    b::addresses()
}

#[napi]
pub struct NativeClient {
    inner: crate::Client,
}
#[napi]
impl NativeClient {
    #[napi(factory)]
    pub fn anonymous() -> Self {
        Self {
            inner: crate::Client::anonymous(),
        }
    }
    #[napi(factory)]
    pub async fn load(name: String) -> Result<Self> {
        crate::Client::load(name)
            .await
            .map(|inner| Self { inner })
            .map_err(err)
    }
    #[napi(factory)]
    pub async fn load_from(path: String) -> Result<Self> {
        crate::Client::load_from(path)
            .await
            .map(|inner| Self { inner })
            .map_err(err)
    }
    #[napi]
    pub async fn name(&self) -> Option<String> {
        self.inner.name().await
    }
    #[napi]
    pub async fn sign(&self, data: Buffer) -> Result<Buffer> {
        b::sign(&self.inner, data.to_vec())
            .await
            .map(Into::into)
            .map_err(err)
    }
    #[napi]
    pub async fn reload(&self) -> Result<()> {
        self.inner.reload().await.map_err(err)
    }
    #[napi]
    pub async fn close(&self) {
        self.inner.close().await;
    }
    #[napi]
    pub async fn local_authority(&self) -> Result<Option<Authority>> {
        self.inner
            .local_authority()
            .await
            .map_err(err)?
            .as_ref()
            .map(b::Authority::local)
            .transpose()
            .map(|a| a.map(Into::into))
            .map_err(err)
    }
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        &self,
        method: String,
        url: String,
        headers: Vec<Header>,
        has_body: bool,
        timeout_ms: Option<u32>,
        owner_hash: Option<String>,
        trailers: Vec<Header>,
    ) -> Result<NativeExchange> {
        b::init(Vec::new(), None).await.map_err(err)?;
        b::Exchange::start(
            &self.inner,
            method,
            url,
            fields(headers),
            has_body,
            timeout_ms,
            owner_hash,
            fields(trailers),
        )
        .await
        .map(|inner| NativeExchange { inner })
        .map_err(err)
    }
    #[napi]
    pub async fn listen(
        &self,
        scopes: Vec<String>,
        handler: &NativeHandler,
    ) -> Result<NativeListener> {
        let callback = handler.callback.clone();
        b::init(Vec::new(), None).await.map_err(err)?;
        let listener = self
            .inner
            .listen(b::scopes(scopes).map_err(err)?, move |request| {
                let callback = callback.clone();
                async move {
                    let (incoming, response) = b::Incoming::new(request);
                    let result = callback
                        .call_async_catch(
                            (NativeIncoming {
                                inner: Arc::new(incoming),
                            },)
                                .into(),
                        )
                        .await
                        .map_err(callback_error)?;
                    if let Either::A(promise) = result {
                        promise.await.map_err(callback_error)?;
                    }
                    response.await.map_err(|_| {
                        Error::new(ErrorCode::Producer, "handler did not return a response")
                    })
                }
            })
            .await
            .map_err(err)?;
        Ok(NativeListener { inner: listener })
    }
}
type Callback = ::napi::threadsafe_function::ThreadsafeFunction<
    FnArgs<(NativeIncoming,)>,
    Either<Promise<()>, ()>,
    FnArgs<(NativeIncoming,)>,
    ::napi::Status,
    false,
    true,
>;
#[napi]
pub struct NativeHandler {
    callback: Arc<Callback>,
}
#[napi]
impl NativeHandler {
    #[napi(constructor)]
    pub fn new(
        handler: Function<'_, FnArgs<(NativeIncoming,)>, Either<Promise<()>, ()>>,
    ) -> Result<Self> {
        let callback = handler
            .build_threadsafe_function::<FnArgs<(NativeIncoming,)>>()
            .callee_handled::<false>()
            .weak::<true>()
            .build()?;
        Ok(Self {
            callback: Arc::new(callback),
        })
    }
}
#[napi]
pub struct NativeExchange {
    inner: b::Exchange,
}
#[napi]
impl NativeExchange {
    #[napi]
    pub async fn response(&self) -> Result<NativeResponse> {
        self.inner
            .response()
            .await
            .map(|inner| NativeResponse { inner })
            .map_err(err)
    }
    #[napi]
    pub async fn write(&self, bytes: Buffer) -> Result<()> {
        self.inner
            .writer()
            .map_err(err)?
            .send(bytes)
            .await
            .map_err(err)
    }
    #[napi]
    pub async fn finish(&self, trailers: Vec<Header>) -> Result<()> {
        self.inner
            .writer()
            .map_err(err)?
            .finish(b::headers(fields(trailers)).map_err(err)?)
            .await
            .map_err(err)
    }
    #[napi]
    pub fn fail(&self, message: String) {
        if let Some(upload) = &self.inner.upload {
            upload.fail(Error::new(ErrorCode::Producer, message));
        }
    }
    #[napi]
    pub fn cancel(&self) {
        self.inner.cancellation.cancel();
    }
    #[napi]
    pub async fn closed(&self) {
        if let Some(upload) = &self.inner.upload {
            upload.closed().await;
        }
    }
}
#[napi]
pub struct NativeResponse {
    inner: crate::ClientResponse,
}
#[napi]
impl NativeResponse {
    #[napi(getter)]
    pub fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }
    #[napi(getter)]
    pub fn headers(&self) -> Vec<Header> {
        headers(b::fields(self.inner.headers()))
    }
    #[napi]
    pub fn authority(&self) -> Result<Option<Authority>> {
        self.inner
            .extensions()
            .get::<dhttp::RemoteAuthority>()
            .map(b::Authority::remote)
            .transpose()
            .map(|a| a.map(Into::into))
            .map_err(err)
    }
    #[napi]
    pub async fn read(&self) -> Result<Option<Buffer>> {
        self.inner
            .body()
            .next()
            .await
            .map(|bytes| bytes.map(|bytes| bytes.to_vec().into()))
            .map_err(err)
    }
    #[napi]
    pub async fn trailers(&self) -> Result<Vec<Header>> {
        self.inner
            .body()
            .trailers()
            .await
            .map(|map| headers(b::fields(&map)))
            .map_err(err)
    }
    #[napi]
    pub fn cancel(&self) {
        self.inner.body().cancel();
    }
}
#[napi]
pub struct NativeIncoming {
    inner: Arc<b::Incoming>,
}
#[napi]
impl NativeIncoming {
    #[napi]
    pub fn local_authority(&self) -> Result<Authority> {
        b::Authority::local(self.inner.local_authority().map_err(err)?)
            .map(Into::into)
            .map_err(err)
    }
    #[napi]
    pub async fn sign(&self, data: Buffer) -> Result<Buffer> {
        b::sign_authority(self.inner.local_authority().map_err(err)?, data.as_ref())
            .map(Into::into)
            .map_err(err)
    }
    #[napi(getter)]
    pub fn method(&self) -> String {
        self.inner.request.method().to_string()
    }
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.inner.request.uri().to_string()
    }
    #[napi(getter)]
    pub fn headers(&self) -> Vec<Header> {
        headers(b::fields(self.inner.request.headers()))
    }
    #[napi]
    pub fn authority(&self) -> Result<Option<Authority>> {
        self.inner
            .request
            .extensions()
            .get::<dhttp::HandshakeSummary>()
            .and_then(|h| h.remote.as_ref())
            .map(b::Authority::remote)
            .transpose()
            .map(|a| a.map(Into::into))
            .map_err(err)
    }
    #[napi]
    pub async fn read(&self) -> Result<Option<Buffer>> {
        self.inner
            .request
            .body()
            .next()
            .await
            .map(|bytes| bytes.map(|bytes| bytes.to_vec().into()))
            .map_err(err)
    }
    #[napi]
    pub async fn trailers(&self) -> Result<Vec<Header>> {
        self.inner
            .request
            .body()
            .trailers()
            .await
            .map(|map| headers(b::fields(&map)))
            .map_err(err)
    }
    #[napi]
    pub fn cancel(&self) {
        self.inner.request.body().cancel();
    }
    #[napi]
    pub async fn closed(&self) {
        self.inner.request.body().closed().await;
    }
    #[napi]
    pub fn respond(&self, status: u16, headers: Vec<Header>) -> Result<NativeUpload> {
        self.inner
            .respond(status, fields(headers))
            .map(|inner| NativeUpload { inner })
            .map_err(err)
    }
}
#[napi]
pub struct NativeUpload {
    inner: crate::UploadWriter,
}
#[napi]
impl NativeUpload {
    #[napi]
    pub async fn write(&self, bytes: Buffer) -> Result<()> {
        self.inner.send(bytes).await.map_err(err)
    }
    #[napi]
    pub async fn finish(&self, trailers: Vec<Header>) -> Result<()> {
        self.inner
            .finish(b::headers(fields(trailers)).map_err(err)?)
            .await
            .map_err(err)
    }
    #[napi]
    pub fn fail(&self, message: String) {
        self.inner.fail(Error::new(ErrorCode::Producer, message));
    }
    #[napi]
    pub async fn closed(&self) {
        self.inner.closed().await;
    }
}
#[napi]
pub struct NativeListener {
    inner: crate::Listener,
}
#[napi]
impl NativeListener {
    #[napi]
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

#[napi]
pub fn verify_signature(public_key: Buffer, data: Buffer, signature: Buffer) -> Result<bool> {
    b::verify(public_key.to_vec(), data.to_vec(), signature.to_vec()).map_err(err)
}
