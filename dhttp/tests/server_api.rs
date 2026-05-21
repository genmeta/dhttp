use std::future::Future;

use dhttp::{
    endpoint::server::{self, ReadRequestHeaderError, Request, Response},
    h3x::endpoint::server::UnresolvedRequest,
};

fn assert_read_request_header<F, Fut>(_f: F)
where
    F: FnOnce(UnresolvedRequest) -> Fut,
    Fut: Future<Output = Result<(Request, Response), ReadRequestHeaderError>>,
{
}

fn assert_response_finish<F, Fut>(_f: F)
where
    F: for<'a> FnOnce(&'a mut Response) -> Option<Fut>,
    Fut: Future<Output = Result<(), server::MessageStreamError>> + Send,
{
}

#[test]
fn server_header_reader_is_public() {
    assert_read_request_header(server::read_request_header);
}

#[test]
fn response_finish_hook_is_public() {
    assert_response_finish(Response::finish);
}
