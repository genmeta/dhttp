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
