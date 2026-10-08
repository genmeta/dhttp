use dhttp_api::{Error, ErrorCode};
use std::error::Error as _;

#[test]
fn protocol_errors_retain_their_code_across_body_and_io_boundaries() {
    let h3 = h3x::ErrorCode::MessageError.stream("invalid DATA");
    let direct = Error::from(dhttp::Error::from(h3.clone()));
    let boxed: dhttp::BoxError = Box::new(h3.clone());
    let boxed = Error::from(boxed);
    let io = Error::from(std::io::Error::other(h3.clone()));
    let core_io = Error::from(dhttp::Error::from(std::io::Error::other(h3)));
    for error in [direct, boxed, io, core_io] {
        assert_eq!(error.code, ErrorCode::Protocol);
        assert_eq!(
            error.protocol_code,
            Some(h3x::ErrorCode::MessageError.as_u64())
        );
        assert!(error.source().is_some());
    }
}

#[test]
fn producer_errors_retain_their_original_source_and_category() {
    let error = Error::producer(std::io::Error::other("broken producer"));
    let boxed: dhttp::BoxError = Box::new(error.clone());
    let boxed = Error::from(boxed);
    let io = Error::from(std::io::Error::other(error.clone()));
    let core_io = Error::from(dhttp::Error::from(std::io::Error::other(error)));
    for error in [boxed, io, core_io] {
        assert_eq!(error.code, ErrorCode::Producer);
        assert_eq!(error.source().unwrap().to_string(), "broken producer");
    }
}
