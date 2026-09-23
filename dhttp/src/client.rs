//! Endpoint-bound outgoing request and response interfaces.
//!
//! Request dispatch is not implemented yet. The types and await outputs match
//! `docs/api/top-level-review.md` so callers can compile against the API.

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    task::{Context, Poll},
};

use h3x::{ArcWndBuf, R, W};

use crate::{Endpoint, HeaderMap, HeaderName, HeaderValue, Method, Result, Uri};

/// An editable outgoing request bound to one Endpoint.
///
/// `B` is the prepared request body: `()` for an empty body or `ArcWndBuf` for
/// a caller-written streaming body. Network I/O begins when await is polled.
#[must_use = "configure and await the request to send it"]
pub struct Request<B> {
    endpoint: Endpoint,
    message: http::Request<B>,
}

impl<B> Request<B> {
    pub fn method(&self) -> &Method {
        self.message.method()
    }

    pub fn set_method(&mut self, method: Method) -> &mut Self {
        *self.message.method_mut() = method;
        self
    }

    pub fn uri(&self) -> &Uri {
        self.message.uri()
    }

    pub fn set_uri(&mut self, uri: Uri) -> &mut Self {
        *self.message.uri_mut() = uri;
        self
    }

    pub fn headers(&self) -> &HeaderMap {
        self.message.headers()
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.message.headers_mut()
    }

    /// Add or replace a header while configuring the request.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.message.headers_mut().insert(name, value);
        self
    }

    pub fn append_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.message.headers_mut().append(name, value);
        self
    }
}

impl Request<()> {
    /// Let the caller write a request body, including for methods such as GET.
    pub fn with_body(self) -> Request<ArcWndBuf> {
        let (head, ()) = self.message.into_parts();
        Request {
            endpoint: self.endpoint,
            message: http::Request::from_parts(head, ArcWndBuf::new(64 * 1024)),
        }
    }
}

impl Request<ArcWndBuf> {
    /// Complete the request with an empty body when it is sent.
    pub fn without_body(self) -> Request<()> {
        let (head, _) = self.message.into_parts();
        Request {
            endpoint: self.endpoint,
            message: http::Request::from_parts(head, ()),
        }
    }
}

/// Awaitable response headers for a request with a caller-written body.
///
/// The task must already be driving h3x::ReadResponse before this is returned.
/// Awaiting yields the original h3x response with its streaming body.
#[must_use = "await the response or cancel the exchange"]
pub struct Response {
    task: tokio::task::JoinHandle<Result<h3x::Response<R>>>,
}

impl Future for Response {
    type Output = Result<h3x::Response<R>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("await the response task and map task failure to a DHTTP error")
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl IntoFuture for Request<()> {
    type Output = Result<h3x::Response<R>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'static>>;

    fn into_future(self) -> Self::IntoFuture {
        todo!("send an empty request body and await response headers")
    }
}

impl IntoFuture for Request<ArcWndBuf> {
    type Output = Result<(h3x::Request<W>, Response)>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'static>>;

    fn into_future(self) -> Self::IntoFuture {
        todo!("start concurrent request writing and response reading")
    }
}
