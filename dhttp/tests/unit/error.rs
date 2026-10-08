use super::*;
use std::error::Error as _;

#[test]
fn protocol_category_and_source_survive_erased_and_nested_io_boundaries() {
    let h3 = h3x::ErrorCode::MessageError.stream("invalid DATA");
    let boxed: crate::BoxError = Box::new(h3.clone());
    let boxed_io: crate::BoxError = Box::new(std::io::Error::other(h3.clone()));
    let nested = std::io::Error::other(std::io::Error::other(h3.clone()));
    for error in [
        Error::from(h3.clone()),
        Error::from(boxed),
        Error::from(boxed_io),
        Error::from(nested),
    ] {
        assert!(matches!(&error, Error::Http3 { source } if source.as_ref() == &h3));
        assert_eq!(
            error.source().unwrap().downcast_ref::<h3x::Error>(),
            Some(&h3)
        );
    }
}

#[test]
fn core_categories_survive_box_and_io_boundaries() {
    let boxed: crate::BoxError = Box::new(Error::RemoteIdentityChanged);
    assert!(matches!(Error::from(boxed), Error::RemoteIdentityChanged));
    assert!(matches!(
        Error::from(std::io::Error::other(Error::AlreadyListening)),
        Error::AlreadyListening
    ));
}

#[test]
fn ordinary_io_and_unknown_body_errors_keep_their_original_causes() {
    let error = Error::from(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "access denied",
    ));
    assert!(
        matches!(&error, Error::Io { source } if source.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(error.source().unwrap().to_string(), "access denied");
    let boxed: crate::BoxError = Box::new(std::fmt::Error);
    let Error::Io { source } = Error::from(boxed) else {
        panic!("unknown body errors remain I/O errors");
    };
    assert!(
        source
            .get_ref()
            .unwrap()
            .downcast_ref::<std::fmt::Error>()
            .is_some()
    );
}
