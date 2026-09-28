//! Directory location and credential loading, without a home runtime or index.

use std::sync::Arc;

use crate::{Error, Result};

/// Resolve the default identity files using DHTTP_HOME or the user's .dhttp
/// directory. No implicit directory creation, registration or network startup.
pub(crate) async fn load_identity(servername: &str) -> Result<Arc<qbase::endpoint::Endpoint>> {
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
