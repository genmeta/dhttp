use super::*;

#[test]
fn discovers_only_direct_profiles_with_ssl() {
    let root = std::env::temp_dir().join(format!(
        "dhttp-home-discovery-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("alice/ssl")).unwrap();
    std::fs::create_dir_all(root.join("bob/ssl")).unwrap();
    std::fs::create_dir_all(root.join("Bad/ssl")).unwrap();
    std::fs::create_dir_all(root.join("charlie")).unwrap();
    let found = DhttpHome::new(root.clone())
        .discover_identity_profiles()
        .unwrap();
    assert_eq!(
        found
            .iter()
            .map(|profile| profile.name())
            .collect::<Vec<_>>(),
        ["alice.dhttp.net", "bob.dhttp.net"]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsafe_identity_path_name() {
    let home = DhttpHome::new(PathBuf::from("/tmp/dhttp-home"));
    assert!(home.join_identity_name("../alice").is_err());
    assert!(home.join_identity_name("alice/name").is_err());
}

#[test]
fn identity_profile_from_path_uses_directory_name_as_dhttp_name() {
    let profile = IdentityProfile::try_from(PathBuf::from("/tmp/reimu.pilot")).unwrap();

    assert_eq!(profile.path(), Path::new("/tmp/reimu.pilot"));
    assert_eq!(profile.name(), "reimu.pilot.dhttp.net");
}

#[test]
fn identity_profile_from_path_rejects_path_without_directory_name() {
    let error = IdentityProfile::try_from(Path::new("/")).unwrap_err();

    assert!(matches!(
        error,
        IdentityProfileFromPathError::MissingFileName { .. }
    ));
}

#[test]
fn identity_profile_from_path_rejects_invalid_directory_name() {
    let error = IdentityProfile::try_from(Path::new("/tmp/123")).unwrap_err();

    assert!(matches!(
        error,
        IdentityProfileFromPathError::InvalidName { .. }
    ));
}

#[test]
fn log_paths_use_the_profile_logs_directory() {
    let profile = IdentityProfile::try_from(Path::new("/tmp/reimu.pilot")).unwrap();
    assert_eq!(
        profile.cert_log_path(),
        PathBuf::from("/tmp/reimu.pilot/logs/cert.log")
    );
    assert_eq!(
        profile.access_log_path(),
        PathBuf::from("/tmp/reimu.pilot/logs/access.log")
    );
}

#[test]
fn shared_layout_paths_use_the_profile_directory() {
    let profile = IdentityProfile::try_from(Path::new("/tmp/reimu.pilot")).unwrap();
    assert_eq!(
        profile.config_db_path(),
        PathBuf::from("/tmp/reimu.pilot/config.db")
    );
    assert_eq!(
        profile.access_db_path(),
        PathBuf::from("/tmp/reimu.pilot/db/access.db")
    );
    assert_eq!(profile.apps_dir(), PathBuf::from("/tmp/reimu.pilot/apps"));
    assert_eq!(
        profile.public_dir(),
        PathBuf::from("/tmp/reimu.pilot/public")
    );
}
