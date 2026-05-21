use bytes::Bytes;
use http::{Method, Uri};
use tokio::sync::Mutex;

use super::{
    Result, code_from_u64, header_pairs, parse_header_name, parse_header_value, parse_headers,
    parse_method, parse_uri,
};
use crate::error::DhttpError;

pub struct Request {
    inner: dhttp::endpoint::client::Request,
}

impl Request {
    pub(crate) fn new(inner: dhttp::endpoint::client::Request) -> Self {
        Self { inner }
    }

    pub fn method(&self, method: &str) -> Result<()> {
        self.set_method_value(parse_method("client_request.method", method)?);
        Ok(())
    }

    pub(crate) fn set_method_value(&self, method: Method) {
        self.inner.set_method(method);
    }

    pub fn uri(&self, uri: &str) -> Result<()> {
        self.set_uri_value(parse_uri("client_request.uri", uri)?);
        Ok(())
    }

    pub(crate) fn set_uri_value(&self, uri: Uri) {
        self.inner.set_uri(uri);
    }

    pub fn header(&self, name: &str, value: &str) -> Result<()> {
        self.inner.set_header(
            parse_header_name("client_request.header", name)?,
            parse_header_value("client_request.header", value)?,
        );
        Ok(())
    }

    pub fn headers(&self, headers: Vec<(String, String)>) -> Result<()> {
        self.inner
            .set_headers(parse_headers("client_request.headers", headers)?);
        Ok(())
    }

    pub fn body(&self, content: Vec<u8>) {
        self.inner.set_body(Bytes::from(content));
    }

    pub fn trailer(&self, name: &str, value: &str) -> Result<()> {
        self.inner.set_trailer(
            parse_header_name("client_request.trailer", name)?,
            parse_header_value("client_request.trailer", value)?,
        );
        Ok(())
    }

    pub fn trailers(&self, trailers: Vec<(String, String)>) -> Result<()> {
        self.inner
            .set_trailers(parse_headers("client_request.trailers", trailers)?);
        Ok(())
    }

    pub fn set_method(&self, method: &str) -> Result<()> {
        self.method(method)
    }

    pub fn set_uri(&self, uri: &str) -> Result<()> {
        self.uri(uri)
    }

    pub fn set_header(&self, name: &str, value: &str) -> Result<()> {
        self.header(name, value)
    }

    pub fn set_headers(&self, headers: Vec<(String, String)>) -> Result<()> {
        self.headers(headers)
    }

    pub fn set_body(&self, content: Vec<u8>) {
        self.body(content);
    }

    pub fn set_trailer(&self, name: &str, value: &str) -> Result<()> {
        self.trailer(name, value)
    }

    pub fn set_trailers(&self, trailers: Vec<(String, String)>) -> Result<()> {
        self.trailers(trailers)
    }

    pub async fn write(&self, content: Vec<u8>) -> Result<()> {
        self.inner
            .write(Bytes::from(content))
            .await
            .map(|_| ())
            .map_err(|error| DhttpError::from_error("client_request.write", error))
    }

    pub async fn flush(&self) -> Result<()> {
        self.inner
            .flush()
            .await
            .map(|_| ())
            .map_err(|error| DhttpError::from_error("client_request.flush", error))
    }

    pub async fn close(&self) -> Result<()> {
        self.inner
            .close()
            .await
            .map_err(|error| DhttpError::from_error("client_request.close", error))
    }

    pub async fn cancel(&self, code: u64) -> Result<()> {
        let code = code_from_u64("client_request.cancel", code)?;
        self.inner
            .cancel(code)
            .await
            .map_err(|error| DhttpError::from_error("client_request.cancel", error))
    }

    pub async fn response(&self) -> Result<Response> {
        self.inner
            .response()
            .await
            .map(Response::new)
            .map_err(|error| DhttpError::from_error("client_request.response", error))
    }

    pub async fn into_response(self) -> Result<Response> {
        self.inner
            .into_response()
            .await
            .map(Response::new)
            .map_err(|error| DhttpError::from_error("client_request.into_response", error))
    }
}

impl From<dhttp::endpoint::client::Request> for Request {
    fn from(request: dhttp::endpoint::client::Request) -> Self {
        Self::new(request)
    }
}

impl From<Request> for dhttp::endpoint::client::Request {
    fn from(request: Request) -> Self {
        request.inner
    }
}

pub struct Response {
    inner: std::sync::Arc<Mutex<Option<dhttp::endpoint::client::Response>>>,
}

impl Response {
    pub(crate) fn new(inner: dhttp::endpoint::client::Response) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(Some(inner))),
        }
    }

    pub async fn into_core(self) -> Result<dhttp::endpoint::client::Response> {
        let inner = std::sync::Arc::try_unwrap(self.inner).map_err(|_| {
            DhttpError::from_message(
                "client_response.into_core",
                "response still has shared handles",
            )
        })?;
        inner.into_inner().ok_or_else(|| {
            DhttpError::from_message("client_response.into_core", "response is closed")
        })
    }

    pub async fn next_response(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.next_response", "response is closed")
        })?;
        response
            .next_response()
            .await
            .map(|_| ())
            .map_err(|error| DhttpError::from_error("client_response.next_response", error))
    }

    pub fn status(&self) -> Result<u16> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message("client_response.status", "response is busy"))?;
        let response = guard.as_ref().ok_or_else(|| {
            DhttpError::from_message("client_response.status", "response is closed")
        })?;
        Ok(response.status().as_u16())
    }

    pub fn headers(&self) -> Result<Vec<(String, String)>> {
        let mut guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message("client_response.headers", "response is busy"))?;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.headers", "response is closed")
        })?;
        header_pairs("client_response.headers", response.headers())
    }

    pub fn header(&self, name: &str) -> Result<Option<String>> {
        let name = parse_header_name("client_response.header", name)?;
        let mut guard = self
            .inner
            .try_lock()
            .map_err(|_| DhttpError::from_message("client_response.header", "response is busy"))?;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.header", "response is closed")
        })?;
        response
            .header(name)
            .map(|value| {
                value
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|error| DhttpError::from_error("client_response.header", error))
            })
            .transpose()
    }

    pub async fn read(&self) -> Result<Option<Vec<u8>>> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.read", "response is closed")
        })?;
        response
            .read()
            .await
            .map(|result| {
                result
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| DhttpError::from_error("client_response.read", error))
            })
            .transpose()
    }

    pub async fn read_to_bytes(&self) -> Result<Vec<u8>> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.read_to_bytes", "response is closed")
        })?;
        response
            .read_to_bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|error| DhttpError::from_error("client_response.read_to_bytes", error))
    }

    pub async fn read_to_string(&self) -> Result<String> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.read_to_string", "response is closed")
        })?;
        response
            .read_to_string()
            .await
            .map_err(|error| DhttpError::from_error("client_response.read_to_string", error))
    }

    pub async fn trailers(&self) -> Result<Vec<(String, String)>> {
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.trailers", "response is closed")
        })?;
        let trailers = response
            .trailers()
            .await
            .map_err(|error| DhttpError::from_error("client_response.trailers", error))?;
        header_pairs("client_response.trailers", trailers)
    }

    pub async fn stop(&self, code: u64) -> Result<()> {
        let code = code_from_u64("client_response.stop", code)?;
        let mut guard = self.inner.lock().await;
        let response = guard.as_mut().ok_or_else(|| {
            DhttpError::from_message("client_response.stop", "response is closed")
        })?;
        response
            .stop(code)
            .await
            .map_err(|error| DhttpError::from_error("client_response.stop", error))
    }

    pub fn agent_name(&self) -> Result<String> {
        let guard = self.inner.try_lock().map_err(|_| {
            DhttpError::from_message("client_response.agent_name", "response is busy")
        })?;
        let response = guard.as_ref().ok_or_else(|| {
            DhttpError::from_message("client_response.agent_name", "response is closed")
        })?;
        Ok(response.agent().name().to_owned())
    }
}

impl From<dhttp::endpoint::client::Response> for Response {
    fn from(response: dhttp::endpoint::client::Response) -> Self {
        Self::new(response)
    }
}
