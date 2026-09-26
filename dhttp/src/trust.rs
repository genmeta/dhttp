//! Private process-wide trust initialization using the qtls-owned TLS types.

use std::sync::Arc;

use crate::{Error, Result, bootstrap::DHTTP_ROOT_CA_DER};

/// Called during Network initialization, before any qconn TLS configuration.
/// Install the build-time DHTTP root CA into qtls::RootCerts; compilation-time
/// DHTTP_ROOT_CA_PEM remains the override. Never disable peer verification.
pub(crate) fn initialize() -> Result<()> {
    qtls::RootCerts::set([DHTTP_ROOT_CA_DER.to_vec().into()]).map_err(|source| Error::TlsConfig {
        source: Arc::new(source),
    })
}
