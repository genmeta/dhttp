use super::*;

#[tokio::test]
async fn close_cancels_owned_operations_waits_for_cleanup_and_keeps_other_owners_open() {
    let first = Scope::new();
    let second = Scope::new();
    let operation = first.register().unwrap();
    let task = tokio::spawn(async move {
        operation.state.cancel.cancelled().await;
        assert_eq!(operation.state.error().code, ErrorCode::Closed);
        drop(operation);
    });
    first.close().await;
    task.await.unwrap();
    assert!(first.register().is_err());
    assert!(second.register().is_ok());
    first.close().await;
}

#[tokio::test]
async fn dropping_the_last_owner_cancels_operations_without_a_reference_cycle() {
    let owner = Scope::new();
    let clone = owner.clone();
    let operation = owner.register().unwrap();
    drop(owner);
    assert!(!operation.state.cancel.is_cancelled());
    drop(clone);
    assert!(operation.state.cancel.is_cancelled());
}

#[tokio::test]
async fn first_failure_survives_later_cancellation() {
    let state = OperationState::new();
    state.fail(Error::new(ErrorCode::Producer, "upload failed"));
    state.fail(Error::cancelled());
    assert_eq!(state.error().code, ErrorCode::Producer);
}
