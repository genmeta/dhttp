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
