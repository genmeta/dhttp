//! Temporary CA/profiles for SDK acceptance tests; never uses the user's home.
#[path = "../../dhttp/tests/support/credentials.rs"]
mod credentials;
fn main() {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).expect("profile root argument"));
    credentials::generate(
        &root,
        &[
            ("server", "server.dhttp.net"),
            ("alice", "alice.dhttp.net"),
            ("bob", "bob.dhttp.net"),
        ],
    );
}
