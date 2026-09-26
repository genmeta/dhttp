use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("dhttp-home-{name}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&path).expect("test temp dir should be creatable");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_profile(home: &std::path::Path, name: &str) -> PathBuf {
    let profile = home.join(name);
    fs::create_dir_all(profile.join(SSL_DIR_NAME))
        .expect("identity profile ssl directory should be creatable");
    profile
}

include!("ssl/candidates.rs");
include!("ssl/credentials.rs");
include!("ssl/saving.rs");
