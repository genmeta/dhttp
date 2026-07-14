use std::{
    iter,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use futures::{Stream, StreamExt, stream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{
    fs::{self, ReadDir},
    io::{self, AsyncWriteExt},
};
use x509_parser::prelude::Pem;

use dhttp_identity::{identity::Identity, name::DhttpName};

use crate::{
    DhttpHome,
    identity::{IdentityProfile, IdentityProfileFromPathError},
};

pub const SSL_DIR_NAME: &str = "ssl";
pub const CERT_FILE_NAME: &str = "fullchain.crt";
pub const KEY_FILE_NAME: &str = "privkey.pem";

static SAVE_IDENTITY_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ResolveIdentityProfileError {
    #[snafu(display("failed to inspect exact identity profile path {}", path.display()))]
    ExactMetadata { path: PathBuf, source: io::Error },
    #[snafu(display("failed to inspect wildcard identity profile path {}", path.display()))]
    WildcardMetadata { path: PathBuf, source: io::Error },
    #[snafu(display("exact identity profile path does not exist: {}", path.display()))]
    ExactNotFound { path: PathBuf },
    #[snafu(display("wildcard identity profile path does not exist: {}", path.display()))]
    WildcardNotFound { path: PathBuf },
    #[snafu(display(
        "identity profile does not exist at exact path {} or wildcard path {}",
        exact.display(),
        wildcard.display()
    ))]
    NotFound { exact: PathBuf, wildcard: PathBuf },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadCertsError {
    #[snafu(display("failed to read certificate file {}", path.display()))]
    Read { path: PathBuf, source: io::Error },
    #[snafu(display("failed to parse pem block in {}", path.display()))]
    Pem {
        path: PathBuf,
        source: x509_parser::error::PEMError,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadKeyError {
    #[snafu(display("failed to inspect private key file {}", path.display()))]
    Metadata { path: PathBuf, source: io::Error },
    #[snafu(display("failed to read private key file {}", path.display()))]
    Read { path: PathBuf, source: io::Error },
    #[snafu(display(
        "private key file permissions are too open at {} (current {current:o}, expected to be 400)",
        path.display()
    ))]
    PermissionsTooOpen { path: PathBuf, current: u32 },
    #[snafu(display("failed to parse private key file {}", path.display()))]
    Parse {
        path: PathBuf,
        source: rustls::pki_types::pem::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadIdentityError {
    #[snafu(display("failed to load identity certificates at {}", path.display()))]
    LoadCerts {
        path: PathBuf,
        source: LoadCertsError,
    },

    #[snafu(display("failed to load identity private key at {}", path.display()))]
    LoadKey { path: PathBuf, source: LoadKeyError },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveIdentityError {
    #[snafu(display("failed to create identity directory at {}", path.display()))]
    CreateIdentityDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to create staged identity material at {}", path.display()))]
    CreateStageDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to get metadata for path {}", path.display()))]
    Metadata { path: PathBuf, source: io::Error },
    #[snafu(display(
        "failed to preserve old identity material from {} at {}",
        from.display(),
        to.display()
    ))]
    PreserveOld {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[snafu(display("failed to create file at {}", path.display()))]
    Create { path: PathBuf, source: io::Error },
    #[snafu(display("failed to write to file at {}", path.display()))]
    Write { path: PathBuf, source: io::Error },
    #[snafu(display("failed to commit identity material at {}", path.display()))]
    Commit { path: PathBuf, source: io::Error },
    #[snafu(display(
        "failed to restore old identity material from {} to {}",
        from.display(),
        to.display()
    ))]
    Rollback {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ListIdentityProfilesError {
    #[snafu(display("failed to list identity profiles in directory {}", path.display()))]
    ReadDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to read filetype of {}", path.display()))]
    ReadFty { path: PathBuf, source: io::Error },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum IdentityProfileCandidateError {
    #[snafu(display("failed to inspect identity profile entry {}", path.display()))]
    EntryMetadata { path: PathBuf, source: io::Error },
    #[snafu(display("invalid identity profile directory {}", path.display()))]
    InvalidProfile {
        path: PathBuf,
        source: IdentityProfileFromPathError,
    },
    #[snafu(display(
        "identity profile {} is missing SSL directory {}",
        profile.name(),
        path.display()
    ))]
    MissingSslDirectory {
        profile: IdentityProfile,
        path: PathBuf,
    },
    #[snafu(display(
        "failed to inspect SSL directory {} for identity profile {}",
        path.display(),
        profile.name()
    ))]
    SslMetadata {
        profile: IdentityProfile,
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display(
        "SSL path {} for identity profile {} is not a directory",
        path.display(),
        profile.name()
    ))]
    SslNotDirectory {
        profile: IdentityProfile,
        path: PathBuf,
    },
}

impl IdentityProfile {
    pub fn ssl_dir(&self) -> PathBuf {
        self.join(SSL_DIR_NAME)
    }

    pub async fn load_certs(&self) -> Result<Vec<CertificateDer<'static>>, LoadCertsError> {
        let certs_path = self.ssl_dir().join(CERT_FILE_NAME);
        let mut data = std::io::Cursor::new(fs::read(certs_path.as_path()).await.context(
            load_certs_error::ReadSnafu {
                path: certs_path.clone(),
            },
        )?);
        let (end_entity_pem, _read) = Pem::read(&mut data).context(load_certs_error::PemSnafu {
            path: certs_path.clone(),
        })?;
        let mut certs = vec![CertificateDer::from(end_entity_pem.contents)];
        loop {
            match Pem::read(&mut data) {
                Ok((pem, _read)) => {
                    certs.push(CertificateDer::from(pem.contents));
                }
                Err(x509_parser::error::PEMError::MissingHeader) => break,
                result => {
                    _ = result.context(load_certs_error::PemSnafu {
                        path: certs_path.clone(),
                    })?;
                }
            }
        }

        Ok(certs)
    }

    pub async fn load_key(&self) -> Result<PrivateKeyDer<'static>, LoadKeyError> {
        let key_path = self.ssl_dir().join(KEY_FILE_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            use snafu::ensure;
            let metadata =
                fs::metadata(key_path.as_path())
                    .await
                    .context(load_key_error::MetadataSnafu {
                        path: key_path.clone(),
                    })?;
            let permissions = metadata.mode() & 0o777;
            ensure!(
                permissions == 0o400,
                load_key_error::PermissionsTooOpenSnafu {
                    path: key_path.clone(),
                    current: permissions
                }
            )
        }

        let data = fs::read(key_path.as_path())
            .await
            .context(load_key_error::ReadSnafu {
                path: key_path.clone(),
            })?;
        rustls::pki_types::pem::PemObject::from_pem_slice(&data).context(
            load_key_error::ParseSnafu {
                path: key_path.clone(),
            },
        )
    }

    /// Load this profile's identity (certificate chain + private key) from disk.
    pub async fn load_identity(&self) -> Result<Identity, LoadIdentityError> {
        let certs_path = self.ssl_dir().join(CERT_FILE_NAME);
        let certs = self
            .load_certs()
            .await
            .context(load_identity_error::LoadCertsSnafu { path: certs_path })?;

        let key_path = self.ssl_dir().join(KEY_FILE_NAME);
        let key = self
            .load_key()
            .await
            .context(load_identity_error::LoadKeySnafu { path: key_path })?;

        Ok(Identity::new(self.name.clone().into_name(), certs, key))
    }

    pub async fn save_identity(&self, cert: &[u8], key: &[u8]) -> Result<(), SaveIdentityError> {
        self.save_identity_transaction(cert, key, || Ok(())).await
    }

    async fn save_identity_transaction<F>(
        &self,
        cert: &[u8],
        key: &[u8],
        before_install: F,
    ) -> Result<(), SaveIdentityError>
    where
        F: FnOnce() -> io::Result<()>,
    {
        fs::create_dir_all(self.path())
            .await
            .context(save_identity_error::CreateIdentityDirSnafu { path: self.path() })?;

        let transaction_id = SAVE_IDENTITY_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        let unique_suffix = format!("{}-{transaction_id}", std::process::id());
        let stage_dir = self.join(format!(".{SSL_DIR_NAME}-stage-{unique_suffix}"));
        let backup_dir = self.join(format!(".{SSL_DIR_NAME}-backup-{unique_suffix}"));
        let ssl_dir = self.ssl_dir();

        fs::create_dir(stage_dir.as_path()).await.context(
            save_identity_error::CreateStageDirSnafu {
                path: stage_dir.clone(),
            },
        )?;

        if let Err(error) = Self::write_material_file(stage_dir.join(CERT_FILE_NAME), cert).await {
            let _ = fs::remove_dir_all(stage_dir.as_path()).await;
            return Err(error);
        }
        if let Err(error) = Self::write_material_file(stage_dir.join(KEY_FILE_NAME), key).await {
            let _ = fs::remove_dir_all(stage_dir.as_path()).await;
            return Err(error);
        }

        let had_old_material = match fs::symlink_metadata(ssl_dir.as_path()).await {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                let _ = fs::remove_dir_all(stage_dir.as_path()).await;
                return Err(save_identity_error::MetadataSnafu { path: ssl_dir }.into_error(error));
            }
        };

        if had_old_material
            && let Err(error) = fs::rename(ssl_dir.as_path(), backup_dir.as_path()).await
        {
            let _ = fs::remove_dir_all(stage_dir.as_path()).await;
            return Err(save_identity_error::PreserveOldSnafu {
                from: ssl_dir,
                to: backup_dir,
            }
            .into_error(error));
        }

        let commit_result = match before_install() {
            Ok(()) => fs::rename(stage_dir.as_path(), ssl_dir.as_path()).await,
            Err(error) => Err(error),
        };

        if let Err(commit_error) = commit_result {
            if had_old_material
                && let Err(rollback_error) =
                    fs::rename(backup_dir.as_path(), ssl_dir.as_path()).await
            {
                let _ = fs::remove_dir_all(stage_dir.as_path()).await;
                return Err(save_identity_error::RollbackSnafu {
                    from: backup_dir,
                    to: ssl_dir,
                }
                .into_error(rollback_error));
            }

            let _ = fs::remove_dir_all(stage_dir.as_path()).await;
            return Err(save_identity_error::CommitSnafu { path: ssl_dir }.into_error(commit_error));
        }

        if had_old_material {
            // The new material is already committed. Backup removal is best-effort so a
            // housekeeping error cannot turn a successful replacement into a reported
            // failure whose observable state contradicts the result.
            let _ = fs::remove_dir_all(backup_dir.as_path()).await;
        }

        Ok(())
    }

    async fn write_material_file(path: PathBuf, contents: &[u8]) -> Result<(), SaveIdentityError> {
        let mut open_options = fs::OpenOptions::new();
        open_options.create_new(true).write(true);
        #[cfg(unix)]
        open_options.mode(0o400);

        let mut file = open_options
            .open(path.as_path())
            .await
            .context(save_identity_error::CreateSnafu { path: path.clone() })?;
        file.write_all(contents)
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;
        file.flush()
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;
        file.sync_all()
            .await
            .context(save_identity_error::WriteSnafu { path })
    }
}

impl DhttpHome {
    /// Resolve `name` to an `IdentityProfile` by exact match only (no wildcard fallback).
    pub async fn resolve_identity_profile_exactly(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        let profile_path = self.join_identity_name(name.clone());
        match fs::metadata(profile_path.as_path()).await {
            Ok(_) => Ok(IdentityProfile {
                path: profile_path,
                name: name.to_owned(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                resolve_identity_profile_error::ExactNotFoundSnafu { path: profile_path }.fail()
            }
            Err(error) => Err(error)
                .context(resolve_identity_profile_error::ExactMetadataSnafu { path: profile_path }),
        }
    }

    /// Resolve `name` to an `IdentityProfile` by wildcard match only (no exact fallback).
    pub async fn resolve_identity_profile_wildcard(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        let wildcard_name = name.to_wildcard();
        let profile_path = self.join_identity_name(wildcard_name.clone());
        match fs::metadata(profile_path.as_path()).await {
            Ok(_) => Ok(IdentityProfile {
                path: profile_path,
                name: wildcard_name,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                resolve_identity_profile_error::WildcardNotFoundSnafu { path: profile_path }.fail()
            }
            Err(error) => {
                Err(error).context(resolve_identity_profile_error::WildcardMetadataSnafu {
                    path: profile_path,
                })
            }
        }
    }

    /// Resolve `name` to an `IdentityProfile`, trying exact match then wildcard match.
    pub async fn resolve_identity_profile(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        match self.resolve_identity_profile_exactly(name.clone()).await {
            Ok(profile) => Ok(profile),
            Err(ResolveIdentityProfileError::ExactNotFound { path: exact }) => {
                match self.resolve_identity_profile_wildcard(name).await {
                    Ok(profile) => Ok(profile),
                    Err(ResolveIdentityProfileError::WildcardNotFound { path: wildcard }) => {
                        resolve_identity_profile_error::NotFoundSnafu { exact, wildcard }.fail()
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Stream the names of all identity profiles that look like a valid
    /// `<name>/ssl/` layout under this home directory.
    pub fn identity_profile_names(
        &self,
    ) -> impl Stream<Item = Result<DhttpName<'static>, ListIdentityProfilesError>> {
        use list_identity_profiles_error::*;
        async fn next_name(
            read_dir: &mut ReadDir,
            path: &Path,
        ) -> Result<Option<DhttpName<'static>>, ListIdentityProfilesError> {
            loop {
                let Some(e) = read_dir.next_entry().await.context(ReadDirSnafu { path })? else {
                    return Ok(None);
                };
                if let (entry_path, name) = (e.path(), e.file_name())
                    && e.file_type()
                        .await
                        .context(ReadFtySnafu {
                            path: entry_path.clone(),
                        })?
                        .is_dir()
                    && let Ok(name) = name.to_string_lossy().as_ref().parse::<DhttpName>()
                    && fs::metadata(entry_path.join(SSL_DIR_NAME)).await.is_ok()
                {
                    return Ok(Some(name));
                }
            }
        }

        let path = self.as_path();
        stream::once(fs::read_dir(path)).flat_map(move |result| {
            match result.context(ReadDirSnafu { path }) {
                Err(error) => stream::iter(iter::once(Err(error))).right_stream(),
                Ok(read_dir) => stream::unfold(read_dir, move |mut read_dir| async move {
                    match next_name(&mut read_dir, path).await {
                        Ok(Some(name)) => Some((Ok(name), read_dir)),
                        Ok(None) => None,
                        Err(e) => Some((Err(e), read_dir)),
                    }
                })
                .left_stream(),
            }
        })
    }

    /// List identity-profile candidates in deterministic native path order.
    ///
    /// Directory enumeration failures abort discovery. Each candidate's metadata,
    /// name, and SSL-layout failure remains attached to that candidate so a bad
    /// sibling cannot hide valid profiles.
    pub async fn identity_profile_candidates(
        &self,
    ) -> Result<
        Box<[Result<IdentityProfile, IdentityProfileCandidateError>]>,
        ListIdentityProfilesError,
    > {
        use identity_profile_candidate_error::*;
        use list_identity_profiles_error::ReadDirSnafu;

        let home_path = self.as_path();
        let mut read_dir = fs::read_dir(home_path)
            .await
            .context(ReadDirSnafu { path: home_path })?;
        let mut paths = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .context(ReadDirSnafu { path: home_path })?
        {
            paths.push(entry.path());
        }
        paths.sort();

        let mut candidates = Vec::new();
        for path in paths {
            let metadata = match fs::metadata(&path).await {
                Ok(metadata) => metadata,
                Err(source) => {
                    candidates.push(Err(EntryMetadataSnafu { path }.into_error(source)));
                    continue;
                }
            };
            if !metadata.is_dir() {
                continue;
            }

            let profile = match IdentityProfile::try_from(path.clone()) {
                Ok(profile) => profile,
                Err(source) => {
                    candidates.push(Err(InvalidProfileSnafu { path }.into_error(source)));
                    continue;
                }
            };
            let ssl_path = profile.ssl_dir();

            match fs::symlink_metadata(&ssl_path).await {
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    candidates.push(
                        MissingSslDirectorySnafu {
                            profile,
                            path: ssl_path,
                        }
                        .fail(),
                    );
                    continue;
                }
                Err(source) => {
                    candidates.push(Err(SslMetadataSnafu {
                        profile,
                        path: ssl_path,
                    }
                    .into_error(source)));
                    continue;
                }
            }

            let ssl_metadata = match fs::metadata(&ssl_path).await {
                Ok(metadata) => metadata,
                Err(source) => {
                    candidates.push(Err(SslMetadataSnafu {
                        profile,
                        path: ssl_path,
                    }
                    .into_error(source)));
                    continue;
                }
            };
            if !ssl_metadata.is_dir() {
                candidates.push(
                    SslNotDirectorySnafu {
                        profile,
                        path: ssl_path,
                    }
                    .fail(),
                );
                continue;
            }

            candidates.push(Ok(profile));
        }

        Ok(candidates.into_boxed_slice())
    }

    pub async fn identity_profile_exists_exactly(&self, name: DhttpName<'_>) -> bool {
        self.resolve_identity_profile_exactly(name).await.is_ok()
    }

    pub async fn identity_profile_exists_wildcard(&self, name: DhttpName<'_>) -> bool {
        self.resolve_identity_profile_wildcard(name).await.is_ok()
    }

    pub async fn identity_profile_exists(&self, name: DhttpName<'_>) -> bool {
        self.resolve_identity_profile(name).await.is_ok()
    }
}

#[cfg(feature = "settings")]
mod settings_integration {
    use snafu::{OptionExt, ResultExt, Snafu};

    use super::ResolveIdentityProfileError;
    use crate::{
        DhttpHome,
        identity::{
            IdentityProfile,
            settings::{DhttpSettingsFile, FileLineCol, LoadDhttpSettingsError},
        },
    };

    #[derive(Snafu, Debug)]
    #[snafu(module, display(
        "failed to resolve default identity profile{}",
        location.as_ref().map_or(String::new(), |loc| format!(" at {loc}"))
    ))]
    pub struct ResolveDefaultIdentityFromSettingsError {
        location: Option<FileLineCol>,
        source: ResolveIdentityProfileError,
    }

    #[derive(Debug, Snafu)]
    #[snafu(module)]
    pub enum ResolveDefaultIdentityProfileError {
        #[snafu(transparent)]
        LoadSettings { source: LoadDhttpSettingsError },
        #[snafu(display("no default identity configured"))]
        NoDefaultIdentity,
        #[snafu(transparent)]
        Resolve {
            source: ResolveDefaultIdentityFromSettingsError,
        },
    }

    impl DhttpSettingsFile {
        /// Resolve the default identity profile referenced by `[default].name`,
        /// or return `None` if no default is configured in this settings file.
        pub async fn resolve_default_identity_profile(
            &self,
            home: &DhttpHome,
        ) -> Option<Result<IdentityProfile, ResolveDefaultIdentityFromSettingsError>> {
            let name = self.settings().default.name.as_ref()?;

            Some(
                home.resolve_identity_profile(name.as_ref().clone())
                    .await
                    .context(
                    resolve_default_identity_from_settings_error::ResolveDefaultIdentityFromSettingsSnafu {
                        location: self.locate(name.span().start),
                    },
                ),
            )
        }
    }

    impl DhttpHome {
        /// Read the settings file and resolve the default identity profile it points to.
        pub async fn resolve_default_identity_profile(
            &self,
        ) -> Result<IdentityProfile, ResolveDefaultIdentityProfileError> {
            Ok(self
                .load_settings()
                .await?
                .resolve_default_identity_profile(self)
                .await
                .context(resolve_default_identity_profile_error::NoDefaultIdentitySnafu)??)
        }
    }
}

#[cfg(feature = "settings")]
pub use settings_integration::*;

#[cfg(test)]
mod tests {
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
            let path = std::env::temp_dir()
                .join(format!("dhttp-home-{name}-{}-{stamp}", std::process::id()));
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
                .is_ok_and(|profile| profile.name().as_full() == "z.good.dhttp.net")
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
            .map(|candidate| candidate.as_ref().unwrap().name().as_full())
            .collect();

        assert_eq!(names, ["a.example.dhttp.net", "z.example.dhttp.net"]);
    }

    #[tokio::test]
    async fn candidates_ignore_regular_home_files() {
        let temp = TempDir::new("candidate-ignore-files");
        fs::write(temp.path().join("settings.toml"), b"[default]\n").unwrap();
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
        assert_eq!(
            names[0].as_ref().unwrap().as_full(),
            "reimu.pilot.dhttp.net"
        );
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
    async fn missing_key_reports_key_metadata_path() {
        let temp = TempDir::new("missing-key");
        let profile = IdentityProfile::try_from(temp.path().join("reimu.pilot")).unwrap();

        let error = profile.load_key().await.unwrap_err();

        match error {
            LoadKeyError::Metadata { path, .. } => {
                assert_eq!(path, profile.ssl_dir().join(KEY_FILE_NAME));
            }
            other => panic!("expected key metadata error, got {other:?}"),
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
        tokio::fs::write(profile.join("server.conf"), b"keep me")
            .await
            .unwrap();

        profile
            .save_identity(b"new cert", b"new key")
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
            tokio::fs::read(profile.join("server.conf")).await.unwrap(),
            b"keep me"
        );
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

        let error = profile
            .save_identity_transaction(b"new cert", b"new key", || {
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
    }

    #[tokio::test]
    async fn missing_identity_profile_reports_exact_and_wildcard_paths() {
        let temp = TempDir::new("missing-identity-profile");
        let home = DhttpHome::new(temp.path().to_path_buf());
        let name = "reimu.pilot".parse().unwrap();

        let error = home.resolve_identity_profile(name).await.unwrap_err();

        match error {
            ResolveIdentityProfileError::NotFound { exact, wildcard } => {
                assert_eq!(exact, temp.path().join("reimu.pilot"));
                assert_eq!(wildcard, temp.path().join("*.pilot"));
            }
            other => panic!("expected not-found error, got {other:?}"),
        }
    }
}
