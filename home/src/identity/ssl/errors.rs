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
