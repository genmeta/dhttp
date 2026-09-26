//! Directory location and credential loading, without a home runtime or index.

use std::{path::Path, sync::Arc};

use rustls::pki_types::pem::PemObject;

use crate::{Error, Result};

/// Resolve the default identity files using DHTTP_HOME or the user's .dhttp
/// directory. No implicit directory creation, registration or network startup.
pub(crate) async fn load_identity(servername: &str) -> Result<Arc<qbase::endpoint::Endpoint>> {
    let canonical = dhttp_home::normalize_name(servername).ok_or_else(|| Error::InvalidName {
        name: servername.to_owned(),
    })?;
    if canonical != servername {
        return Err(Error::InvalidName {
            name: servername.to_owned(),
        });
    }
    let root = dhttp_home::DhttpHome::load(dhttp_home::HomeScope::User).map_err(|error| {
        Error::HomeUnavailable {
            message: error.to_string(),
        }
    })?;
    let profile = root
        .identity_profile(servername)
        .map_err(|_| Error::InvalidName {
            name: servername.to_owned(),
        })?;
    let certificate_chain = profile.cert_path();
    if !tokio::fs::try_exists(&certificate_chain)
        .await
        .map_err(|source| Error::Home {
            path: certificate_chain.clone(),
            source: Arc::new(source),
        })?
    {
        return Err(Error::IdentityNotFound {
            name: servername.to_owned(),
        });
    }
    let certificates = profile.load_certs().await.map_err(|source| Error::Home {
        path: certificate_chain,
        source: Arc::new(source),
    })?;
    let private_key = profile.key_path();
    let key = profile.load_key().await.map_err(|source| Error::Home {
        path: private_key,
        source: Arc::new(source),
    })?;
    let ocsp_staple = profile.ocsp_path();
    let ocsp = profile.load_ocsp().await.map_err(|source| Error::Home {
        path: ocsp_staple,
        source: Arc::new(source),
    })?;
    qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        servername,
        certificates,
        key,
        ocsp,
    )
    .map_err(|source| Error::Credentials {
        source: Arc::new(source),
    })
}

/// Read the explicit certificate chain, private key and OCSP staple together.
/// Errors preserve the failing path; failure never publishes a partial endpoint.
pub(crate) async fn load_identity_from_files(
    servername: &str,
    certificate_chain: &Path,
    private_key: &Path,
    ocsp_staple: &Path,
) -> Result<Arc<qbase::endpoint::Endpoint>> {
    let certificates = tokio::fs::read(certificate_chain)
        .await
        .map_err(|source| Error::Home {
            path: certificate_chain.to_owned(),
            source: Arc::new(source),
        })?;
    let certificates = qtls::CertificateDer::pem_slice_iter(&certificates)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| Error::Home {
            path: certificate_chain.to_owned(),
            source: Arc::new(source),
        })?;
    if certificates.is_empty() {
        return Err(Error::HomeUnavailable {
            message: format!("no certificates in {}", certificate_chain.display()),
        });
    }
    let key = tokio::fs::read(private_key)
        .await
        .map_err(|source| Error::Home {
            path: private_key.to_owned(),
            source: Arc::new(source),
        })?;
    let key = qtls::PrivateKeyDer::from_pem_slice(&key).map_err(|source| Error::Home {
        path: private_key.to_owned(),
        source: Arc::new(source),
    })?;
    let ocsp = tokio::fs::read(ocsp_staple)
        .await
        .map_err(|source| Error::Home {
            path: ocsp_staple.to_owned(),
            source: Arc::new(source),
        })?;
    if ocsp.is_empty() {
        return Err(Error::HomeUnavailable {
            message: format!("OCSP staple is empty: {}", ocsp_staple.display()),
        });
    }
    qbase::endpoint::Endpoint::new(
        &qtls::default_provider(),
        servername,
        certificates,
        key,
        ocsp,
    )
    .map_err(|source| Error::Credentials {
        source: Arc::new(source),
    })
}
