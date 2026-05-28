use std::{
    iter,
    path::{Path, PathBuf},
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

use crate::{DhttpHome, identity::IdentityProfile};

pub const SSL_DIR_NAME: &str = "ssl";
pub const CERT_FILE_NAME: &str = "fullchain.crt";
pub const KEY_FILE_NAME: &str = "privkey.pem";

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
    #[snafu(display("failed to get metadata for path {}", path.display()))]
    Metadata { path: PathBuf, source: io::Error },
    #[snafu(display("failed to delete old file at {}", path.display()))]
    Delete { path: PathBuf, source: io::Error },
    #[snafu(display("failed to create file at {}", path.display()))]
    Create { path: PathBuf, source: io::Error },
    #[snafu(display("failed to write to file at {}", path.display()))]
    Write { path: PathBuf, source: io::Error },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ListIdentityProfilesError {
    #[snafu(display("failed to list identity profiles in directory {}", path.display()))]
    ReadDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to read filetype of {}", path.display()))]
    ReadFty { path: PathBuf, source: io::Error },
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
        let metadata =
            fs::metadata(key_path.as_path())
                .await
                .context(load_key_error::MetadataSnafu {
                    path: key_path.clone(),
                })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            use snafu::ensure;
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
        let ssl_dir = self.ssl_dir();
        fs::create_dir_all(ssl_dir.as_path()).await.context(
            save_identity_error::CreateIdentityDirSnafu {
                path: ssl_dir.clone(),
            },
        )?;

        let mut open_options = fs::OpenOptions::new();
        open_options.create_new(true).write(true);
        #[cfg(unix)]
        open_options.mode(0o400);

        let path = ssl_dir.join(CERT_FILE_NAME);
        if let Err(error) = fs::remove_file(path.as_path()).await
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(save_identity_error::DeleteSnafu { path }.into_error(error));
        }
        open_options
            .open(path.as_path())
            .await
            .context(save_identity_error::CreateSnafu { path: path.clone() })?
            .write_all(cert)
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;

        let path = ssl_dir.join(KEY_FILE_NAME);
        if let Err(error) = fs::remove_file(path.as_path()).await
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(save_identity_error::DeleteSnafu { path }.into_error(error));
        }
        open_options
            .open(path.as_path())
            .await
            .context(save_identity_error::CreateSnafu { path: path.clone() })?
            .write_all(key)
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;

        Ok(())
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
