use std::future::Future;

use dhttp::{
    endpoint::server::{self, Request, ResolveError, Response},
    h3x::endpoint::UnresolvedRequest,
};

fn assert_resolve<F, Fut>(_f: F)
where
    F: FnOnce(UnresolvedRequest) -> Fut,
    Fut: Future<Output = Result<(Request, Response), ResolveError>>,
{
}

fn assert_response_finish<F, Fut>(_f: F)
where
    F: for<'a> FnOnce(&'a mut Response) -> Option<Fut>,
    Fut: Future<Output = Result<(), server::MessageStreamError>> + Send,
{
}

#[test]
fn server_resolve_hook_is_public() {
    assert_resolve(server::resolve);
}

#[test]
fn response_finish_hook_is_public() {
    assert_response_finish(Response::finish);
}
