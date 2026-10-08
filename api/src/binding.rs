//! Conversion and native handle ownership shared by N-API and PyO3.
use crate::{
    Cancellation, Client, Error, ErrorCode, RequestOptions, ResponseFuture, Result, ServerRequest,
    ServerResponse, UploadWriter,
};
use http::HeaderMap;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

pub type Fields = Vec<(String, Vec<u8>)>;

pub fn headers(fields: Fields) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(invalid)?;
        let value = http::HeaderValue::from_bytes(&value).map_err(invalid)?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn fields(headers: &HeaderMap) -> Fields {
    headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect()
}

pub fn invalid(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::InvalidArgument, error.to_string())
}

pub struct Exchange {
    pub response: tokio::sync::Mutex<Option<ResponseFuture>>,
    pub upload: Option<UploadWriter>,
    pub cancellation: Cancellation,
}

impl Exchange {
    // Positional values are the language boundary; HTTP stays in std Request.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        client: &Client,
        method: String,
        uri: String,
        fields: Fields,
        has_body: bool,
        timeout_ms: Option<u32>,
        owner_hash: Option<String>,
        trailers: Fields,
    ) -> Result<Self> {
        let (upload, body) = if has_body {
            let (writer, body) = crate::upload_channel();
            (Some(writer), Some(body))
        } else {
            (None, None)
        };
        let mut request = http::Request::builder()
            .method(method.as_str())
            .uri(uri)
            .body(body)
            .map_err(invalid)?;
        *request.headers_mut() = headers(fields)?;
        let end = h3x::Trailers::default();
        for (name, value) in headers(trailers)?.iter() {
            end.append(name.clone(), value.clone());
        }
        request.extensions_mut().insert(end);
        let response = client
            .request(
                request,
                RequestOptions {
                    timeout: timeout_ms.map(|millis| Duration::from_millis(millis.into())),
                    expected_remote_owner_hash: owner_hash
                        .as_deref()
                        .map(dhttp_home::certificate::OwnerHash::try_from)
                        .transpose()
                        .map_err(invalid)?,
                },
            )
            .await?;
        let cancellation = response.cancellation();
        Ok(Self {
            response: tokio::sync::Mutex::new(Some(response)),
            upload,
            cancellation,
        })
    }
    pub async fn response(&self) -> Result<crate::ClientResponse> {
        let future = self
            .response
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::new(ErrorCode::Closed, "response already taken"))?;
        future.await
    }
    pub fn writer(&self) -> Result<&UploadWriter> {
        self.upload
            .as_ref()
            .ok_or_else(|| invalid("request has no upload body"))
    }
}

pub struct Incoming {
    pub request: ServerRequest,
    pub response: Mutex<Option<oneshot::Sender<ServerResponse>>>,
}
impl Incoming {
    pub fn local_authority(&self) -> Result<&dhttp::LocalAuthority> {
        self.request
            .extensions()
            .get::<dhttp::HandshakeSummary>()
            .and_then(|summary| summary.local.as_ref())
            .ok_or_else(|| Error::new(ErrorCode::Identity, "missing local handshake identity"))
    }
    pub fn new(request: ServerRequest) -> (Self, oneshot::Receiver<ServerResponse>) {
        let (send, receive) = oneshot::channel();
        (
            Self {
                request,
                response: Mutex::new(Some(send)),
            },
            receive,
        )
    }
    pub fn respond(&self, status: u16, fields: Fields) -> Result<UploadWriter> {
        use http_body_util::BodyExt;
        let status = http::StatusCode::from_u16(status).map_err(invalid)?;
        if status.is_informational() {
            return Err(invalid("intermediate responses are not supported"));
        }
        let fields = headers(fields)?;
        let (writer, body) = crate::upload_channel();
        let mut response = http::Response::new(
            body.map_err(|error| Box::new(error) as dhttp::BoxError)
                .boxed_unsync(),
        );
        *response.status_mut() = status;
        *response.headers_mut() = fields;
        self.response
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::new(ErrorCode::Closed, "response already sent"))?
            .send(response)
            .map_err(|_| Error::new(ErrorCode::Closed, "handler cancelled"))?;
        Ok(writer)
    }
}

#[derive(Clone)]
pub struct Authority {
    pub name: String,
    pub certificates: Vec<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub owner_hash: String,
    pub subject_key_identifier: Vec<u8>,
}
impl Authority {
    pub fn new(
        name: &str,
        certificates: &[dhttp::CertificateDer<'_>],
        public_key: &[u8],
    ) -> Result<Self> {
        let identifier =
            dhttp_home::certificate::extract_dhttp_subject_key_identifier(certificates)
                .map_err(|error| Error::new(ErrorCode::Identity, error.to_string()))?;
        let ski = dhttp_home::certificate::extract_subject_key_identifier(certificates)
            .map_err(invalid)?
            .unwrap_or_default()
            .to_vec();
        Ok(Self {
            name: name.to_owned(),
            certificates: certificates
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect(),
            public_key: public_key.to_vec(),
            owner_hash: identifier.owner_hash().to_string(),
            subject_key_identifier: ski,
        })
    }
    pub fn remote(authority: &dhttp::RemoteAuthority) -> Result<Self> {
        Self::new(
            authority.name(),
            authority.certificates(),
            authority.public_key().as_ref(),
        )
    }
    pub fn local(authority: &dhttp::LocalAuthority) -> Result<Self> {
        Self::new(
            authority.name(),
            authority.certificates(),
            authority.public_key().as_ref(),
        )
    }
}

pub fn scopes(names: Vec<String>) -> Result<dhttp::Scopes> {
    let mut scopes = None;
    for name in names {
        let scope = match name.as_str() {
            "loopback" => dhttp::Scope::Loopback,
            "internal" => dhttp::Scope::Internal,
            "external" => dhttp::Scope::External,
            _ => return Err(invalid(format!("unknown scope: {name}"))),
        };
        scopes = Some(match scopes {
            None => scope.into(),
            Some(scopes) => scopes | scope,
        });
    }
    scopes.ok_or_else(|| invalid("at least one listening scope is required"))
}

static PEERS: std::sync::LazyLock<
    Arc<std::sync::RwLock<std::collections::HashMap<String, dhttp::resolve::EndpointAddr>>>,
> = std::sync::LazyLock::new(Default::default);

#[derive(Debug)]
struct PeerResolver;
impl std::fmt::Display for PeerResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK explicit peers")
    }
}
impl dhttp::resolve::Resolve for PeerResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        family: Option<dhttp::resolve::Family>,
    ) -> dhttp::resolve::ResolveFuture<'a> {
        use futures::{FutureExt, StreamExt};
        async move {
            let peer = PEERS.read().unwrap().get(name).copied().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no explicit peer")
            })?;
            let _ = family;
            Ok(futures::stream::iter([(dhttp::resolve::Source::System, peer)]).boxed())
        }
        .boxed()
    }
}

pub async fn init(peers: Vec<(String, String)>, roots: Option<Vec<u8>>) -> Result<()> {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    static ROOTS: tokio::sync::Mutex<Option<Vec<u8>>> = tokio::sync::Mutex::const_new(None);
    let peers = peers
        .into_iter()
        .map(|(name, address)| {
            Ok((
                dhttp_home::normalize_name(&name).ok_or_else(|| invalid("invalid peer name"))?,
                dhttp::resolve::EndpointAddr::direct(address.parse().map_err(invalid)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut configured = ROOTS.lock().await;
    crate::init().await?;
    if let Some(roots) = roots {
        match configured.as_ref() {
            Some(previous) if previous != &roots => {
                return Err(invalid(
                    "root certificates already configured for this process",
                ));
            }
            Some(_) => {}
            None => {
                let certificates = rustls_pemfile::certs(&mut roots.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(invalid)?;
                qtls::RootCerts::set(certificates).map_err(invalid)?;
                *configured = Some(roots);
            }
        }
    }
    INSTALLED.call_once(|| {
        dhttp::resolve::Resolver::add(Arc::new(dhttp::resolve::SystemResolver));
        dhttp::resolve::Resolver::add(Arc::new(PeerResolver));
    });
    PEERS.write().unwrap().extend(peers);
    Ok(())
}

pub fn addresses() -> Vec<String> {
    dhttp::AddressBook::global()
        .inner_bindings()
        .into_iter()
        .map(|(address, _)| address.to_string())
        .collect()
}

pub async fn sign(client: &Client, data: Vec<u8>) -> Result<Vec<u8>> {
    let authority = client
        .local_authority()
        .await?
        .ok_or_else(|| Error::new(ErrorCode::Identity, "anonymous client cannot sign"))?;
    sign_authority(&authority, &data)
}

pub fn sign_authority(authority: &dhttp::LocalAuthority, data: &[u8]) -> Result<Vec<u8>> {
    for scheme in [
        qtls::SignatureScheme::ECDSA_NISTP256_SHA256,
        qtls::SignatureScheme::ECDSA_NISTP384_SHA384,
        qtls::SignatureScheme::ED25519,
        qtls::SignatureScheme::RSA_PKCS1_SHA256,
    ] {
        match authority.sign(scheme, data) {
            Ok(signature) => return Ok(signature),
            Err(qtls::SignError::UnsupportedScheme { .. }) => continue,
            Err(error) => return Err(Error::new(ErrorCode::Identity, error.to_string())),
        }
    }
    Err(Error::new(ErrorCode::Identity, "unsupported signing key"))
}

pub fn verify(public_key: Vec<u8>, data: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
    dhttp_home::certificate::verify_signature(&public_key, &data, &signature).map_err(invalid)
}
