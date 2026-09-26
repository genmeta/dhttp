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
