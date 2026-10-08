use super::*;
use tower_service::Service as _;

fn empty_request() -> http::Request<dhttp::Body> {
    http::Request::new(dhttp::Body::default())
}

#[tokio::test]
async fn exceptions_and_panics_before_headers_produce_an_empty_500() {
    let handlers: Vec<Handler> = vec![
        Arc::new(|_: ServerRequest| {
            async { Err(Error::producer(std::io::Error::other("private exception"))) }.boxed()
        }),
        Arc::new(|_: ServerRequest| {
            panic!("synchronous callback panic");
            #[allow(unreachable_code)]
            futures::future::ready(Ok(http::Response::new(dhttp::Body::default()))).boxed()
        }),
        Arc::new(|_: ServerRequest| {
            async {
                panic!("asynchronous callback panic");
                #[allow(unreachable_code)]
                Ok(http::Response::new(dhttp::Body::default()))
            }
            .boxed()
        }),
    ];
    for handler in handlers {
        let scope = Scope::new();
        let mut service = Service {
            handler,
            scope: scope.clone(),
        };
        let response = service.call(empty_request()).await.unwrap();
        assert_eq!(response.status(), 500);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        scope.close().await;
    }
}

#[tokio::test]
async fn listener_cancellation_stops_handlers_before_headers_and_pending_response_bodies() {
    let scope = Scope::new();
    let mut service = Service {
        handler: Arc::new(|_: ServerRequest| {
            futures::future::pending::<Result<ServerResponse>>().boxed()
        }),
        scope: scope.clone(),
    };
    let mut handling = service.call(empty_request());
    assert!(futures::poll!(&mut handling).is_pending());
    scope.cancel();
    assert!(handling.await.is_err());
    scope.close().await;

    let scope = Scope::new();
    let body = http_body_util::StreamBody::new(futures::stream::pending::<
        std::result::Result<Frame<Bytes>, dhttp::BoxError>,
    >());
    let operation = scope.register().unwrap();
    let mut body = OwnedBody::new(body.boxed_unsync(), operation);
    scope.cancel();
    assert!(body.frame().await.unwrap().is_err());
    scope.close().await;
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn producer_errors_after_headers_stay_body_errors() {
    let scope = Scope::new();
    let body = http_body_util::StreamBody::new(futures::stream::iter(vec![Err::<
        Frame<Bytes>,
        dhttp::BoxError,
    >(Box::new(
        Error::producer(std::io::Error::other("body failed")),
    ))]));
    let operation = scope.register().unwrap();
    let mut body = OwnedBody::new(body.boxed_unsync(), operation);
    assert!(body.frame().await.unwrap().is_err());
    scope.close().await;
}
