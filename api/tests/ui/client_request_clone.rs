fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<dhttp_api::endpoint::client::Request>();
}
