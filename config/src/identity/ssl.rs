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

use crate::{DhttpConfig, identity::IdentityConfig};

pub const SSL_DIR_NAME: &str = "ssl";
pub const CERT_FILE_NAME: &str = "fullchain.crt";
pub const KEY_FILE_NAME: &str = "privkey.pem";

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LocateIdentityError {
    #[snafu(display("failed to inspect exact identity path {}", path.display()))]
    ExactMetadata { path: PathBuf, source: io::Error },
    #[snafu(display("failed to inspect wildcard identity path {}", path.display()))]
    WildcardMetadata { path: PathBuf, source: io::Error },
    #[snafu(display("exact identity path does not exist: {}", path.display()))]
    ExactNotFound { path: PathBuf },
    #[snafu(display("wildcard identity path does not exist: {}", path.display()))]
    WildcardNotFound { path: PathBuf },
    #[snafu(display(
        "identity does not exist at exact path {} or wildcard path {}",
        exact.display(),
        wildcard.display()
    ))]
    NotFound { exact: PathBuf, wildcard: PathBuf },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadIdentityError {
    #[snafu(display("failed to locate identity config"))]
    Locate { source: LocateIdentityError },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadCertError {
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
pub enum LoadIdentitySslError {
    #[snafu(display("failed to load identity certificates at {}", path.display()))]
    LoadCerts {
        path: PathBuf,
        source: LoadCertError,
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
pub enum ListIdentitiesError {
    #[snafu(display("failed to list identities in directory {}", path.display()))]
    ReadDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to read filetype of {}", path.display()))]
    ReadFty { path: PathBuf, source: io::Error },
}

impl IdentityConfig {
    pub fn ssl_dir(&self) -> PathBuf {
        self.join(SSL_DIR_NAME)
    }

    pub async fn certs(&self) -> Result<Vec<CertificateDer<'static>>, LoadCertError> {
        let certs_path = self.ssl_dir().join(CERT_FILE_NAME);
        let mut data = std::io::Cursor::new(fs::read(certs_path.as_path()).await.context(
            load_cert_error::ReadSnafu {
                path: certs_path.clone(),
            },
        )?);
        let (end_entity_pem, _read) = Pem::read(&mut data).context(load_cert_error::PemSnafu {
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
                    _ = result.context(load_cert_error::PemSnafu {
                        path: certs_path.clone(),
                    })?;
                }
            }
        }

        Ok(certs)
    }

    pub async fn key(&self) -> Result<PrivateKeyDer<'static>, LoadKeyError> {
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

    pub async fn identity(&self) -> Result<Identity, LoadIdentitySslError> {
        let certs_path = self.ssl_dir().join(CERT_FILE_NAME);
        let certs = self
            .certs()
            .await
            .context(load_identity_ssl_error::LoadCertsSnafu { path: certs_path })?;

        let key_path = self.ssl_dir().join(KEY_FILE_NAME);
        let key = self
            .key()
            .await
            .context(load_identity_ssl_error::LoadKeySnafu { path: key_path })?;

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

        // remove old cert file if any, then write new one
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

        // remove old key file if any, then write new one
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

impl DhttpConfig {
    pub async fn locate_identity_exactly(
        &self,
        name: DhttpName<'_>,
    ) -> Result<PathBuf, LocateIdentityError> {
        let identity_io = self.join_identity_name(name);
        match fs::metadata(identity_io.as_path()).await {
            Ok(_) => Ok(identity_io),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                locate_identity_error::ExactNotFoundSnafu { path: identity_io }.fail()
            }
            Err(error) => {
                Err(error).context(locate_identity_error::ExactMetadataSnafu { path: identity_io })
            }
        }
    }

    pub async fn locate_identity_wildcard(
        &self,
        name: DhttpName<'_>,
    ) -> Result<PathBuf, LocateIdentityError> {
        let wildcard_name = name.to_wildcard();

        let identity_io = self.join_identity_name(wildcard_name.clone());
        match fs::metadata(identity_io.as_path()).await {
            Ok(_) => Ok(identity_io),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                locate_identity_error::WildcardNotFoundSnafu { path: identity_io }.fail()
            }
            Err(error) => Err(error)
                .context(locate_identity_error::WildcardMetadataSnafu { path: identity_io }),
        }
    }

    pub async fn locate_identity<'a>(
        &self,
        name: DhttpName<'a>,
    ) -> Result<(PathBuf, DhttpName<'a>), LocateIdentityError> {
        match self.locate_identity_exactly(name.clone()).await {
            Ok(location) => Ok((location, name)),
            Err(LocateIdentityError::ExactNotFound { path: exact }) => {
                let wildcard_name = name.to_wildcard();
                match self.locate_identity_wildcard(wildcard_name.clone()).await {
                    Ok(location) => Ok((location, wildcard_name)),
                    Err(LocateIdentityError::WildcardNotFound { path: wildcard }) => {
                        locate_identity_error::NotFoundSnafu { exact, wildcard }.fail()
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn identities(
        &self,
    ) -> impl Stream<Item = Result<DhttpName<'static>, ListIdentitiesError>> {
        use list_identities_error::*;
        async fn next_identity(
            read_dir: &mut ReadDir,
            path: &Path,
        ) -> Result<Option<DhttpName<'static>>, ListIdentitiesError> {
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
                    match next_identity(&mut read_dir, path).await {
                        Ok(Some(name)) => Some((Ok(name), read_dir)),
                        Ok(None) => None,
                        Err(e) => Some((Err(e), read_dir)),
                    }
                })
                .left_stream(),
            }
        })
    }

    pub async fn identity_exists_exactly(&self, name: DhttpName<'_>) -> bool {
        self.locate_identity_exactly(name).await.is_ok()
    }

    pub async fn identity_exists_wildcard(&self, name: DhttpName<'_>) -> bool {
        self.locate_identity_wildcard(name).await.is_ok()
    }

    pub async fn identity_exists(&self, name: DhttpName<'_>) -> bool {
        self.locate_identity(name).await.is_ok()
    }

    pub async fn load_identity_exactly(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityConfig, LoadIdentityError> {
        let identity_io = self
            .locate_identity_exactly(name.clone())
            .await
            .context(load_identity_error::LocateSnafu)?;
        Ok(IdentityConfig {
            path: identity_io,
            name: name.to_owned(),
        })
    }

    pub async fn load_identity_wildcard(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityConfig, LoadIdentityError> {
        let wildcard_name = name.to_wildcard();
        let identity_io = self
            .locate_identity_wildcard(wildcard_name.clone())
            .await
            .context(load_identity_error::LocateSnafu)?;
        Ok(IdentityConfig {
            path: identity_io,
            name: wildcard_name,
        })
    }

    pub async fn load_identity(
        &self,
        name: DhttpName<'_>,
    ) -> Result<IdentityConfig, LoadIdentityError> {
        let (identity_io, name) = self
            .locate_identity(name)
            .await
            .context(load_identity_error::LocateSnafu)?;
        Ok(IdentityConfig {
            path: identity_io,
            name: name.to_owned(),
        })
    }
}

// --- Intersection: ssl + default-config ---

#[cfg(feature = "default-config")]
mod default_config_integration {
    use snafu::{OptionExt, ResultExt, Snafu};

    use super::LoadIdentityError;
    use crate::{
        DhttpConfig,
        identity::{
            IdentityConfig,
            default::{DefaultConfigFile, FileLineCol, LoadDefaultConfigError},
        },
    };

    #[derive(Snafu, Debug)]
    #[snafu(module, display(
        "failed to load identity specified{}",
        config.as_ref().map_or(String::new(), |loc| format!(" at {loc}"))
    ))]
    pub struct LoadDefaultIdentityFromConfigError {
        config: Option<FileLineCol>,
        source: LoadIdentityError,
    }

    #[derive(Debug, Snafu)]
    #[snafu(module)]
    pub enum LoadDefaultIdentityError {
        #[snafu(transparent)]
        LoadDefaultConfig { source: LoadDefaultConfigError },
        #[snafu(display("no default identity configured"))]
        NoDefaultIdentity,
        #[snafu(transparent)]
        LoadIdentity {
            source: LoadDefaultIdentityFromConfigError,
        },
    }

    impl DefaultConfigFile {
        pub async fn load_default_identity(
            &self,
            dhttp_config: &DhttpConfig,
        ) -> Option<Result<IdentityConfig, LoadDefaultIdentityFromConfigError>> {
            let name = self.config().name.as_ref()?;

            Some(
                dhttp_config
                    .load_identity(name.as_ref().clone())
                    .await
                    .context(
                    load_default_identity_from_config_error::LoadDefaultIdentityFromConfigSnafu {
                        config: self.locate(name.span().start),
                    },
                ),
            )
        }
    }

    impl DhttpConfig {
        pub async fn load_default_identity(
            &self,
        ) -> Result<IdentityConfig, LoadDefaultIdentityError> {
            Ok(self
                .load_identity_default_config()
                .await?
                .load_default_identity(self)
                .await
                .context(load_default_identity_error::NoDefaultIdentitySnafu)??)
        }
    }
}

#[cfg(feature = "default-config")]
pub use default_config_integration::*;

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
            let path = std::env::temp_dir().join(format!(
                "dhttp-config-{name}-{}-{stamp}",
                std::process::id()
            ));
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
        let identity = IdentityConfig::try_from(temp.path().join("reimu.pilot")).unwrap();

        let error = identity.certs().await.unwrap_err();

        match error {
            LoadCertError::Read { path, .. } => {
                assert_eq!(path, identity.ssl_dir().join(CERT_FILE_NAME));
            }
            other => panic!("expected certificate read error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_key_reports_key_metadata_path() {
        let temp = TempDir::new("missing-key");
        let identity = IdentityConfig::try_from(temp.path().join("reimu.pilot")).unwrap();

        let error = identity.key().await.unwrap_err();

        match error {
            LoadKeyError::Metadata { path, .. } => {
                assert_eq!(path, identity.ssl_dir().join(KEY_FILE_NAME));
            }
            other => panic!("expected key metadata error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_identity_reports_exact_and_wildcard_paths() {
        let temp = TempDir::new("missing-identity");
        let config = DhttpConfig::new(temp.path().to_path_buf());
        let name = "reimu.pilot".parse().unwrap();

        let error = config.load_identity(name).await.unwrap_err();

        match error {
            LoadIdentityError::Locate {
                source: LocateIdentityError::NotFound { exact, wildcard },
            } => {
                assert_eq!(exact, temp.path().join("reimu.pilot"));
                assert_eq!(wildcard, temp.path().join("*.pilot"));
            }
            other => panic!("expected locate-not-found error, got {other:?}"),
        }
    }
}
