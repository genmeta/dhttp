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

#[tokio::test]
async fn failed_commit_restores_the_complete_old_material_set() {
    let temp = TempDir::new("failed-commit");
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

    let error = profile
        .save_identity_transaction(b"new cert", b"new key", b"new ocsp", || {
            Err(io::Error::other("injected commit failure"))
        })
        .await
        .unwrap_err();

    assert!(
        !error.to_string().contains("injected commit failure"),
        "the semantic error layer must not repeat its source: {error}"
    );
    assert!(
        snafu::Report::from_error(&error)
            .to_string()
            .contains("injected commit failure"),
        "the full error report must retain the source chain"
    );
    assert_eq!(
        tokio::fs::read(profile.ssl_dir().join(CERT_FILE_NAME))
            .await
            .unwrap(),
        b"old cert"
    );
    assert_eq!(
        tokio::fs::read(profile.ssl_dir().join(KEY_FILE_NAME))
            .await
            .unwrap(),
        b"old key"
    );
    assert_eq!(
        tokio::fs::read(profile.ocsp_path()).await.unwrap(),
        b"old ocsp"
    );
}
