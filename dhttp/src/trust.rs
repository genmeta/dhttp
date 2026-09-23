//! Private process-wide trust initialization using the qtls-owned TLS types.

use crate::Result;

/// Called during Network initialization, before any qconn TLS configuration.
/// Install the build-time DHTTP root CA into qtls::RootCerts; compilation-time
/// DHTTP_ROOT_CA_PEM remains the override. Never disable peer verification.
pub(crate) fn initialize() -> Result<()> {
    todo!("initialize qtls roots from the embedded DHTTP trust anchor")
}
