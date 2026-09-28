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

#[tokio::test]
async fn bad_candidate_does_not_hide_valid_sibling() {
    let temp = TempDir::new("candidate-sibling-isolation");
    fs::create_dir_all(temp.path().join("123")).unwrap();
    create_profile(temp.path(), "z.good.dhttp.net");
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.is_ok())
            .count(),
        1
    );
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.is_err())
            .count(),
        1
    );
    assert!(candidates.iter().any(|candidate| {
        candidate
            .as_ref()
            .is_ok_and(|profile| profile.name() == "z.good.dhttp.net")
    }));
}

#[tokio::test]
async fn candidates_are_sorted_by_native_path_before_validation() {
    let temp = TempDir::new("candidate-native-order");
    create_profile(temp.path(), "z.example.dhttp.net");
    create_profile(temp.path(), "a.example.dhttp.net");
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();
    let names: Vec<_> = candidates
        .iter()
        .map(|candidate| candidate.as_ref().unwrap().name())
        .collect();

    assert_eq!(names, ["a.example.dhttp.net", "z.example.dhttp.net"]);
}

#[tokio::test]
async fn candidates_ignore_regular_home_files() {
    let temp = TempDir::new("candidate-ignore-files");
    fs::write(temp.path().join("notes.txt"), b"unrelated file\n").unwrap();
    let profile = create_profile(temp.path(), "reimu.pilot");
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].as_ref().unwrap().path(), profile);
}

#[tokio::test]
async fn invalid_profile_name_is_one_candidate_error() {
    let temp = TempDir::new("candidate-invalid-name");
    let path = temp.path().join("123");
    fs::create_dir_all(&path).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert!(matches!(
        &candidates[0],
        Err(IdentityProfileCandidateError::InvalidProfile {
            path: error_path,
            source: crate::identity::IdentityProfileFromPathError::InvalidName { .. },
        }) if *error_path == path
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn candidate_preserves_profile_entry_metadata_error() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new("candidate-entry-metadata");
    let path = temp.path().join("loop.pilot");
    symlink("loop.pilot", &path).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    match &candidates[0] {
        Err(IdentityProfileCandidateError::EntryMetadata {
            path: error_path,
            source,
        }) => {
            assert_eq!(*error_path, path);
            assert!(source.raw_os_error().is_some());
        }
        other => panic!("expected entry metadata error, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_ssl_directory_is_one_candidate_error() {
    let temp = TempDir::new("candidate-missing-ssl");
    let path = temp.path().join("reimu.pilot");
    fs::create_dir_all(&path).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert!(matches!(
        &candidates[0],
        Err(IdentityProfileCandidateError::MissingSslDirectory { profile, path: ssl_path })
            if profile.path() == path && *ssl_path == path.join(SSL_DIR_NAME)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn broken_ssl_symlink_is_metadata_error_not_missing() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new("candidate-broken-ssl");
    let profile_path = temp.path().join("reimu.pilot");
    fs::create_dir_all(&profile_path).unwrap();
    let ssl_path = profile_path.join(SSL_DIR_NAME);
    symlink("missing-target", &ssl_path).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert!(matches!(
        &candidates[0],
        Err(IdentityProfileCandidateError::SslMetadata { profile, path, .. })
            if profile.path() == profile_path && *path == ssl_path
    ));
}

#[tokio::test]
async fn ssl_path_that_is_not_directory_is_one_candidate_error() {
    let temp = TempDir::new("candidate-ssl-file");
    let profile_path = temp.path().join("reimu.pilot");
    fs::create_dir_all(&profile_path).unwrap();
    let ssl_path = profile_path.join(SSL_DIR_NAME);
    fs::write(&ssl_path, b"not a directory").unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    assert!(matches!(
        &candidates[0],
        Err(IdentityProfileCandidateError::SslNotDirectory { profile, path })
            if profile.path() == profile_path && *path == ssl_path
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn candidate_preserves_ssl_metadata_error() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new("candidate-ssl-metadata");
    let profile_path = temp.path().join("reimu.pilot");
    fs::create_dir_all(&profile_path).unwrap();
    let ssl_path = profile_path.join(SSL_DIR_NAME);
    symlink(SSL_DIR_NAME, &ssl_path).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let candidates = home.identity_profile_candidates().await.unwrap();

    match &candidates[0] {
        Err(IdentityProfileCandidateError::SslMetadata {
            profile,
            path,
            source,
        }) => {
            assert_eq!(profile.path(), profile_path);
            assert_eq!(*path, ssl_path);
            assert!(source.raw_os_error().is_some());
        }
        other => panic!("expected ssl metadata error, got {other:?}"),
    }
}

#[tokio::test]
async fn lenient_profile_names_remains_compatible() {
    let temp = TempDir::new("strict-lenient-compatible");
    create_profile(temp.path(), "reimu.pilot");
    fs::create_dir_all(temp.path().join("123")).unwrap();
    let home = DhttpHome::new(temp.path().to_path_buf());

    let names: Vec<_> = home.identity_profile_names().collect().await;

    assert_eq!(names.len(), 1);
    assert_eq!(names[0].as_ref().unwrap().as_str(), "reimu.pilot.dhttp.net");
}

#[tokio::test]
async fn missing_certificate_reports_certificate_path() {
    let temp = TempDir::new("missing-certificate");
    let profile = IdentityProfile::try_from(temp.path().join("reimu.pilot")).unwrap();

    let error = profile.load_certs().await.unwrap_err();

    match error {
        LoadCertsError::Read { path, .. } => {
            assert_eq!(path, profile.ssl_dir().join(CERT_FILE_NAME));
        }
        other => panic!("expected certificate read error, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_key_reports_key_path() {
    let temp = TempDir::new("missing-key");
    let profile = IdentityProfile::try_from(temp.path().join("reimu.pilot")).unwrap();

    let error = profile.load_key().await.unwrap_err();

    #[cfg(unix)]
    assert!(matches!(
        error,
        LoadKeyError::Metadata { path, .. } if path == profile.ssl_dir().join(KEY_FILE_NAME)
    ));
    #[cfg(not(unix))]
    assert!(matches!(
        error,
        LoadKeyError::Read { path, .. } if path == profile.ssl_dir().join(KEY_FILE_NAME)
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
    let name = "reimu.pilot";

    let error = home.resolve_identity_profile(name).await.unwrap_err();

    match error {
        ResolveIdentityProfileError::NotFound { exact, wildcard } => {
            assert_eq!(exact, temp.path().join("reimu.pilot"));
            assert_eq!(wildcard, temp.path().join("*.pilot"));
        }
        other => panic!("expected not-found error, got {other:?}"),
    }
}

#[tokio::test]
async fn save_identity_replaces_material_without_touching_profile_files() {
    let temp = TempDir::new("replace-material");
    let profile = IdentityProfile::try_from(temp.path().join("alice.smith")).unwrap();
    tokio::fs::create_dir_all(profile.ssl_dir()).await.unwrap();
    tokio::fs::write(profile.ssl_dir().join(CERT_FILE_NAME), b"old cert")
        .await
        .unwrap();
    tokio::fs::write(profile.ssl_dir().join(KEY_FILE_NAME), b"old key")
        .await
        .unwrap();
    tokio::fs::write(profile.ocsp_path(), b"old ocsp")
        .await
        .unwrap();
    tokio::fs::write(profile.config_db_path(), b"keep me")
        .await
        .unwrap();

    profile
        .save_identity(b"new cert", b"new key", b"new ocsp")
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(profile.ssl_dir().join(CERT_FILE_NAME))
            .await
            .unwrap(),
        b"new cert"
    );
    assert_eq!(
        tokio::fs::read(profile.ssl_dir().join(KEY_FILE_NAME))
            .await
            .unwrap(),
        b"new key"
    );
    assert_eq!(
        tokio::fs::read(profile.ocsp_path()).await.unwrap(),
        b"new ocsp"
    );
    assert_eq!(
        tokio::fs::read(profile.config_db_path()).await.unwrap(),
        b"keep me"
    );
}

#[tokio::test]
async fn empty_ocsp_does_not_replace_existing_identity() {
    let temp = TempDir::new("empty-ocsp-save");
    let profile = IdentityProfile::try_from(temp.path().join("alice.smith")).unwrap();
    tokio::fs::create_dir_all(profile.ssl_dir()).await.unwrap();
    tokio::fs::write(profile.ocsp_path(), b"old ocsp")
        .await
        .unwrap();

    assert!(matches!(
        profile.save_identity(b"new cert", b"new key", b"").await,
        Err(SaveIdentityError::EmptyOcsp)
    ));
    assert_eq!(
        tokio::fs::read(profile.ocsp_path()).await.unwrap(),
        b"old ocsp"
    );
    assert!(!profile.cert_path().exists());
}
