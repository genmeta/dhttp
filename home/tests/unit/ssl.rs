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
    fs::create_dir_all(profile.join(SSL_DIR_NAME)).unwrap();
    profile
}

#[tokio::test]
async fn async_names_match_sync_discovery_for_direct_ssl_directories() {
    let temp = TempDir::new("discovery-consistency");
    create_profile(temp.path(), "alice.pilot");
    create_profile(temp.path(), "123");
    create_profile(temp.path(), "*.pilot");
    create_profile(temp.path(), "Bad");
    create_profile(temp.path(), "bad_name");
    fs::create_dir_all(temp.path().join("no-ssl")).unwrap();
    fs::create_dir_all(temp.path().join("ssl-file")).unwrap();
    fs::write(temp.path().join("ssl-file/ssl"), b"not a directory").unwrap();
    fs::write(temp.path().join("notes.txt"), b"unrelated file").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(
            temp.path().join("alice.pilot"),
            temp.path().join("linked-profile"),
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("linked-ssl")).unwrap();
        symlink(
            temp.path().join("alice.pilot/ssl"),
            temp.path().join("linked-ssl/ssl"),
        )
        .unwrap();
    }

    let home = DhttpHome::new(temp.path().to_path_buf());
    let sync_names: Vec<_> = home
        .discover_identity_profiles()
        .unwrap()
        .into_iter()
        .map(|profile| profile.name().to_owned())
        .collect();
    let mut async_names: Vec<_> = home
        .identity_profile_names()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    async_names.sort();

    assert_eq!(async_names, sync_names);
    assert_eq!(
        sync_names,
        [
            "*.pilot.dhttp.net",
            "123.dhttp.net",
            "alice.pilot.dhttp.net"
        ]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn async_names_reject_symlink_home() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new("symlink-home");
    let link = temp.path().join("home-link");
    symlink(temp.path(), &link).unwrap();
    let home = DhttpHome::new(link);
    let names: Vec<_> = home.identity_profile_names().collect().await;
    assert!(matches!(
        names.as_slice(),
        [Err(ListIdentityProfilesError::ReadDir { source, .. })]
            if source.kind() == io::ErrorKind::InvalidInput
    ));
}

#[tokio::test]
async fn missing_certificate_reports_certificate_path() {
    let temp = TempDir::new("missing-certificate");
    let profile = IdentityProfile::try_from(temp.path().join("reimu.pilot")).unwrap();

    let error = profile.load_certs().await.unwrap_err();
    assert!(matches!(
        error,
        LoadCertsError::Read { path, .. } if path == profile.cert_path()
    ));
}

#[tokio::test]
async fn missing_key_reports_key_path() {
    let temp = TempDir::new("missing-key");
    let profile = IdentityProfile::try_from(temp.path().join("reimu.pilot")).unwrap();

    let error = profile.load_key().await.unwrap_err();
    #[cfg(unix)]
    assert!(matches!(
        error,
        LoadKeyError::Metadata { path, .. } if path == profile.key_path()
    ));
    #[cfg(not(unix))]
    assert!(matches!(
        error,
        LoadKeyError::Read { path, .. } if path == profile.key_path()
    ));
}

#[tokio::test]
async fn ocsp_staple_must_exist_and_be_nonempty() {
    let temp = TempDir::new("ocsp-staple");
    let profile = IdentityProfile::try_from(temp.path().join("alice.smith")).unwrap();
    let path = profile.ocsp_path();

    assert!(matches!(
        profile.load_ocsp().await,
        Err(LoadOcspError::Read { path: missing, .. }) if missing == path
    ));
    tokio::fs::create_dir_all(profile.ssl_dir()).await.unwrap();
    tokio::fs::write(&path, []).await.unwrap();
    assert!(matches!(
        profile.load_ocsp().await,
        Err(LoadOcspError::Empty { path: empty }) if empty == path
    ));
    tokio::fs::write(&path, b"staple").await.unwrap();
    assert_eq!(profile.load_ocsp().await.unwrap(), b"staple");
}

#[tokio::test]
async fn missing_identity_profile_reports_exact_and_wildcard_paths() {
    let temp = TempDir::new("missing-identity-profile");
    let home = DhttpHome::new(temp.path().to_path_buf());

    let error = home
        .resolve_identity_profile("reimu.pilot")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ResolveIdentityProfileError::NotFound { exact, wildcard }
            if exact == temp.path().join("reimu.pilot")
                && wildcard == temp.path().join("*.pilot")
    ));
}
