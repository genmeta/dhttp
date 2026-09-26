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
