//! Directory location and credential loading, without a home runtime or index.

use std::{path::Path, sync::Arc};

use crate::Result;

/// Resolve the default identity files using DHTTP_HOME or the user's .dhttp
/// directory. No implicit directory creation, registration or network startup.
pub(crate) async fn load_identity(servername: &str) -> Result<Arc<qbase::endpoint::Endpoint>> {
    todo!("locate and read default identity PEM files")
}

/// Read the explicit certificate chain and private key as one credential load.
/// Errors preserve the failing path; failure never publishes a partial endpoint.
pub(crate) async fn load_identity_from_files(
    servername: &str,
    certificate_chain: &Path,
    private_key: &Path,
) -> Result<Arc<qbase::endpoint::Endpoint>> {
    todo!("read and validate explicit identity PEM files")
}
