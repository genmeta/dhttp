#[test]
fn client_request_is_not_clone() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*_clone.rs");
}
