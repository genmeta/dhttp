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

use crate::identity::{Identity, normalize_profile_name};

use crate::{
    DhttpHome,
    identity::{IdentityProfile, IdentityProfileFromPathError},
};

pub const SSL_DIR_NAME: &str = "ssl";
pub const CERT_FILE_NAME: &str = "fullchain.crt";
pub const KEY_FILE_NAME: &str = "privkey.pem";
pub const OCSP_FILE_NAME: &str = "ocsp.der";

static SAVE_IDENTITY_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ResolveIdentityProfileError {
    #[snafu(display("invalid identity name: {name}"))]
    InvalidName { name: String },
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
pub enum LoadOcspError {
    #[snafu(display("failed to read OCSP staple at {}", path.display()))]
    Read { path: PathBuf, source: io::Error },
    #[snafu(display("OCSP staple is empty at {}", path.display()))]
    Empty { path: PathBuf },
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

    #[snafu(display("failed to load identity OCSP staple at {}", path.display()))]
    LoadOcsp {
        path: PathBuf,
        source: LoadOcspError,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveIdentityError {
    #[snafu(display("identity OCSP staple cannot be empty"))]
    EmptyOcsp,
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

    pub fn cert_path(&self) -> PathBuf {
        self.ssl_dir().join(CERT_FILE_NAME)
    }

    pub fn key_path(&self) -> PathBuf {
        self.ssl_dir().join(KEY_FILE_NAME)
    }

    pub fn ocsp_path(&self) -> PathBuf {
        self.ssl_dir().join(OCSP_FILE_NAME)
    }

    pub async fn load_certs(&self) -> Result<Vec<CertificateDer<'static>>, LoadCertsError> {
        let certs_path = self.cert_path();
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
        let key_path = self.key_path();
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

    pub async fn load_ocsp(&self) -> Result<Vec<u8>, LoadOcspError> {
        let path = self.ocsp_path();
        let bytes = fs::read(&path)
            .await
            .context(load_ocsp_error::ReadSnafu { path: &path })?;
        if bytes.is_empty() {
            return load_ocsp_error::EmptySnafu { path }.fail();
        }
        Ok(bytes)
    }

    /// Load this profile's certificate chain, private key and OCSP staple.
    pub async fn load_identity(&self) -> Result<Identity, LoadIdentityError> {
        let certs_path = self.cert_path();
        let certs = self
            .load_certs()
            .await
            .context(load_identity_error::LoadCertsSnafu { path: certs_path })?;

        let key_path = self.key_path();
        let key = self
            .load_key()
            .await
            .context(load_identity_error::LoadKeySnafu { path: key_path })?;

        let ocsp_path = self.ocsp_path();
        let ocsp = self
            .load_ocsp()
            .await
            .context(load_identity_error::LoadOcspSnafu { path: ocsp_path })?;

        Ok(Identity::new(self.name.clone(), certs, key, ocsp))
    }

    pub async fn save_identity(
        &self,
        cert: &[u8],
        key: &[u8],
        ocsp: &[u8],
    ) -> Result<(), SaveIdentityError> {
        self.save_identity_transaction(cert, key, ocsp, || Ok(()))
            .await
    }

    async fn save_identity_transaction<F>(
        &self,
        cert: &[u8],
        key: &[u8],
        ocsp: &[u8],
        before_install: F,
    ) -> Result<(), SaveIdentityError>
    where
        F: FnOnce() -> io::Result<()>,
    {
        if ocsp.is_empty() {
            return save_identity_error::EmptyOcspSnafu.fail();
        }
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
        if let Err(error) = Self::write_material_file(stage_dir.join(OCSP_FILE_NAME), ocsp).await {
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
        name: &str,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        let canonical = normalize_profile_name(name).ok_or_else(|| {
            ResolveIdentityProfileError::InvalidName {
                name: name.to_owned(),
            }
        })?;
        let profile_path = self.join_identity_name(&canonical).expect("validated name");
        match fs::metadata(profile_path.as_path()).await {
            Ok(_) => Ok(IdentityProfile {
                path: profile_path,
                name: canonical,
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
        name: &str,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        let canonical = normalize_profile_name(name).ok_or_else(|| {
            ResolveIdentityProfileError::InvalidName {
                name: name.to_owned(),
            }
        })?;
        let (_, rest) = canonical.split_once('.').expect("validated name");
        let wildcard_name = format!("*.{rest}");
        let profile_path = self
            .join_identity_name(&wildcard_name)
            .expect("validated name");
        match fs::metadata(profile_path.as_path()).await {
            Ok(_) => Ok(IdentityProfile {
                path: profile_path,
                name: wildcard_name,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                resolve_identity_profile_error::WildcardNotFoundSnafu { path: profile_path }.fail()
            }
            #[cfg(windows)]
            Err(error) if error.kind() == io::ErrorKind::InvalidFilename => {
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
        name: &str,
    ) -> Result<IdentityProfile, ResolveIdentityProfileError> {
        match self.resolve_identity_profile_exactly(name).await {
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
    ) -> impl Stream<Item = Result<String, ListIdentityProfilesError>> {
        use list_identity_profiles_error::*;
        async fn next_name(
            read_dir: &mut ReadDir,
            path: &Path,
        ) -> Result<Option<String>, ListIdentityProfilesError> {
            loop {
                let Some(e) = read_dir.next_entry().await.context(ReadDirSnafu { path })? else {
                    return Ok(None);
                };
                let entry_path = e.path();
                let name = e.file_name();
                if e.file_type()
                    .await
                    .context(ReadFtySnafu {
                        path: entry_path.clone(),
                    })?
                    .is_dir()
                    && let Some(name) = normalize_profile_name(name.to_string_lossy().as_ref())
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

    pub async fn identity_profile_exists_exactly(&self, name: &str) -> bool {
        self.resolve_identity_profile_exactly(name).await.is_ok()
    }

    pub async fn identity_profile_exists_wildcard(&self, name: &str) -> bool {
        self.resolve_identity_profile_wildcard(name).await.is_ok()
    }

    pub async fn identity_profile_exists(&self, name: &str) -> bool {
        self.resolve_identity_profile(name).await.is_ok()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ssl.rs"]
mod tests;
