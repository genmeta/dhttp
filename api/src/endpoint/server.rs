use bytes::Bytes;
use tokio::sync::Mutex;

use super::{
    Result, code_from_u64, header_pairs, parse_header_name, parse_header_value, parse_headers,
    parse_status,
};
use crate::{error::DhttpError, http as api_http};

pub struct Request {
    inner: std::sync::Arc<Mutex<Option<dhttp::endpoint::server::Request>>>,
}

impl Request {
    pub(crate) fn new(inner: dhttp::endpoint::server::Request) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(Some(inner))),
        }
    }

    pub(crate) fn shared_handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    pub async fn into_core(self) -> Result<dhttp::endpoint::server::Request> {
        let inner = std::sync::Arc::try_unwrap(self.inner).map_err(|_| {
            DhttpError::from_message(
                "server_request.into_core",
                "request still has shared handles",
            )
        })?;
        inner.into_inner().ok_or_else(|| {
            DhttpError::from_message("server_request.into_core", "request is closed")
        })
    }

    pub(crate) async fn take(&self) -> Option<dhttp::endpoint::server::Request> {
        self.inner.lock().await.take()
    }

    pub fn method(&self) -> Result<String> {
        self.with_ref("server_request.method", |request| {
            Ok(request.method().to_string())
        })
    }

    pub fn uri(&self) -> Result<String> {
        self.with_ref("server_request.uri", |request| {
            Ok(request.uri().to_string())
        })
    }

    pub fn scheme(&self) -> Result<Option<String>> {
        self.with_ref("server_request.scheme", |request| {
            Ok(request.scheme().map(|scheme| scheme.to_string()))
        })
    }

    pub fn authority(&self) -> Result<Option<String>> {
        self.with_ref("server_request.authority", |request| {
            Ok(request.authority().map(|authority| authority.to_string()))
        })
    }

    pub fn path(&self) -> Result<Option<String>> {
        self.with_ref("server_request.path", |request| {
            Ok(request.path().map(|path| path.to_string()))
        })
    }

    pub fn protocol(&self) -> Result<Option<String>> {
        self.with_ref("server_request.protocol", |request| {
            Ok(request
                .protocol()
                .map(|protocol| protocol.as_str().to_owned()))
        })
    }

    pub fn headers(&self) -> Result<api_http::HeaderPairs> {
        self.with_ref("server_request.headers", |request| {
            header_pairs("server_request.headers", request.headers())
        })
    }

    pub fn header(&self, name: &str) -> Result<Option<String>> {
        let name = parse_header_name("server_request.header", name)?;
        self.with_ref("server_request.header", |request| {
            request
                .header(name)
                .map(|value| {
                    value
                        .to_str()
                        .map(str::to_owned)
                        .map_err(|error| DhttpError::from_error("server_request.header", error))
                })
                .transpose()
        })
    }

    pub async fn read(&self) -> Result<Option<api_http::Body>> {
        let mut guard = self.inner.lock().await;
        let request = guard
            .as_mut()
            .ok_or_else(|| DhttpError::from_message("server_request.read", "request is closed"))?;
        request
            .read()
            .await
            .map(|result| {
                result
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| DhttpError::from_error("server_request.read", error))
            })
            .transpose()
    }

    pub async fn read_to_bytes(&self) -> Result<api_http::Body> {
        let mut guard = self.inner.lock().await;
        let request = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("server_request.read_to_bytes", "request is closed")
        })?;
        request
            .read_to_bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|error| DhttpError::from_error("server_request.read_to_bytes", error))
    }

    pub async fn read_to_string(&self) -> Result<String> {
        let mut guard = self.inner.lock().await;
        let request = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("server_request.read_to_string", "request is closed")
        })?;
        request
            .read_to_string()
            .await
            .map_err(|error| DhttpError::from_error("server_request.read_to_string", error))
    }

    pub async fn trailers(&self) -> Result<api_http::HeaderPairs> {
        let mut guard = self.inner.lock().await;
        let request = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("server_request.trailers", "request is closed")
        })?;
        let trailers = request
            .trailers()
            .await
            .map_err(|error| DhttpError::from_error("server_request.trailers", error))?;
        header_pairs("server_request.trailers", trailers)
    }

    pub async fn stop(&self, code: u64) -> Result<()> {
        let code = code_from_u64("server_request.stop", code)?;
        let mut guard = self.inner.lock().await;
        let request = guard
            .as_mut()
            .ok_or_else(|| DhttpError::from_message("server_request.stop", "request is closed"))?;
        request
            .stop(code)
            .await
            .map_err(|error| DhttpError::from_error("server_request.stop", error))
    }

    pub fn agent_name(&self) -> Result<Option<String>> {
        self.with_ref("server_request.agent_name", |request| {
            Ok(request.agent().map(|agent| agent.name().to_owned()))
        })
    }

    pub fn stream_id(&self) -> Result<u64> {
        self.with_ref("server_request.stream_id", |request| {
            Ok(request.stream_id().into_inner())
        })
    }

    fn with_ref<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&dhttp::endpoint::server::Request) -> Result<T>,
    ) -> Result<T> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message(operation, "request is busy"))?;
        let request = guard
            .as_ref()
            .ok_or_else(|| DhttpError::from_message(operation, "request is closed"))?;
        f(request)
    }
}

impl From<dhttp::endpoint::server::Request> for Request {
    fn from(request: dhttp::endpoint::server::Request) -> Self {
        Self::new(request)
    }
}

pub struct Response {
    inner: std::sync::Arc<Mutex<Option<dhttp::endpoint::server::Response>>>,
}

impl Response {
    pub(crate) fn new(inner: dhttp::endpoint::server::Response) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(Some(inner))),
        }
    }

    pub(crate) fn shared_handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    pub async fn into_core(self) -> Result<dhttp::endpoint::server::Response> {
        let inner = std::sync::Arc::try_unwrap(self.inner).map_err(|_| {
            DhttpError::from_message(
                "server_response.into_core",
                "response still has shared handles",
            )
        })?;
        inner.into_inner().ok_or_else(|| {
            DhttpError::from_message("server_response.into_core", "response is closed")
        })
    }

    pub(crate) async fn take(&self) -> Option<dhttp::endpoint::server::Response> {
        self.inner.lock().await.take()
    }

    pub fn status(&self) -> Result<Option<api_http::Status>> {
        self.with_ref("server_response.status", |response| {
            Ok(response.status().map(|status| status.as_u16()))
        })
    }

    pub fn set_status(&self, status: api_http::Status) -> Result<()> {
        let status = parse_status("server_response.set_status", status)?;
        self.with_mut("server_response.set_status", |response| {
            response.set_status(status);
            Ok(())
        })
    }

    pub fn headers(&self) -> Result<api_http::HeaderPairs> {
        self.with_ref("server_response.headers", |response| {
            header_pairs("server_response.headers", response.headers())
        })
    }

    pub fn set_header(&self, name: &str, value: &str) -> Result<()> {
        let name = parse_header_name("server_response.set_header", name)?;
        let value = parse_header_value("server_response.set_header", value)?;
        self.with_mut("server_response.set_header", |response| {
            response.set_header(name, value);
            Ok(())
        })
    }

    pub fn set_body(&self, content: api_http::Body) -> Result<()> {
        self.with_mut("server_response.set_body", |response| {
            response.set_body(Bytes::from(content));
            Ok(())
        })
    }

    pub async fn write(&self, content: api_http::Body) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("server_response.write", "response is closed")
        })?;
        response
            .write(Bytes::from(content))
            .await
            .map(|_| ())
            .map_err(|error| DhttpError::from_error("server_response.write", error))
    }

    pub async fn flush(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("server_response.flush", "response is closed")
        })?;
        response
            .flush()
            .await
            .map(|_| ())
            .map_err(|error| DhttpError::from_error("server_response.flush", error))
    }

    pub fn trailers(&self) -> Result<api_http::HeaderPairs> {
        self.with_ref("server_response.trailers", |response| {
            header_pairs("server_response.trailers", response.trailers())
        })
    }

    pub fn set_trailer(&self, name: &str, value: &str) -> Result<()> {
        let name = parse_header_name("server_response.set_trailer", name)?;
        let value = parse_header_value("server_response.set_trailer", value)?;
        self.with_mut("server_response.set_trailer", |response| {
            response.set_trailer(name, value);
            Ok(())
        })
    }

    pub fn set_trailers(&self, trailers: api_http::HeaderPairs) -> Result<()> {
        let trailers = parse_headers("server_response.set_trailers", trailers)?;
        self.with_mut("server_response.set_trailers", |response| {
            response.set_trailers(trailers);
            Ok(())
        })
    }

    pub async fn close(&self) -> Result<()> {
        let mut response = self.take_response("server_response.close").await?;
        response
            .close()
            .await
            .map_err(|error| DhttpError::from_error("server_response.close", error))
    }

    pub async fn cancel(&self, code: u64) -> Result<()> {
        let code = code_from_u64("server_response.cancel", code)?;
        self.cancel_code(code).await
    }

    pub(crate) async fn cancel_code(&self, code: h3x::error::Code) -> Result<()> {
        let mut response = self.take_response("server_response.cancel").await?;
        response
            .cancel(code)
            .await
            .map_err(|error| DhttpError::from_error("server_response.cancel", error))
    }

    pub fn agent_name(&self) -> Result<String> {
        self.with_ref("server_response.agent_name", |response| {
            Ok(response.agent().name().to_owned())
        })
    }

    pub fn stream_id(&self) -> Result<u64> {
        self.with_ref("server_response.stream_id", |response| {
            Ok(response.stream_id().into_inner())
        })
    }

    pub async fn finish(&self) -> Result<()> {
        let mut response = self.take_response("server_response.finish").await?;
        if let Some(future) = response.finish() {
            future
                .await
                .map_err(|error| DhttpError::from_error("server_response.finish", error))?;
        }
        Ok(())
    }

    pub(crate) async fn finish_if_open(&self) -> Result<()> {
        let Some(mut response) = self.inner.lock().await.take() else {
            return Ok(());
        };
        if let Some(future) = response.finish() {
            future
                .await
                .map_err(|error| DhttpError::from_error("server_response.finish", error))?;
        }
        Ok(())
    }

    async fn take_response(
        &self,
        operation: &'static str,
    ) -> Result<dhttp::endpoint::server::Response> {
        self.inner
            .lock()
            .await
            .take()
            .ok_or_else(|| DhttpError::from_message(operation, "response is closed"))
    }

    fn with_ref<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&dhttp::endpoint::server::Response) -> Result<T>,
    ) -> Result<T> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message(operation, "response is busy"))?;
        let response = guard
            .as_ref()
            .ok_or_else(|| DhttpError::from_message(operation, "response is closed"))?;
        f(response)
    }

    fn with_mut<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&mut dhttp::endpoint::server::Response) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message(operation, "response is busy"))?;
        let response = guard
            .as_mut()
            .ok_or_else(|| DhttpError::from_message(operation, "response is closed"))?;
        f(response)
    }
}

impl From<dhttp::endpoint::server::Response> for Response {
    fn from(response: dhttp::endpoint::server::Response) -> Self {
        Self::new(response)
    }
}
