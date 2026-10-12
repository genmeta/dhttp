use std::sync::{Arc, LazyLock};

use rustls::{
    RootCertStore,
    client::WebPkiServerVerifier,
    pki_types::CertificateDer,
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};

/// DER-encoded DHTTP ecosystem root CA certificate embedded at build time.
///
/// The build script decodes and validates `DHTTP_ROOT_CA_PEM` when that environment
/// variable is present. Otherwise, it embeds the production default.
pub use crate::bootstrap::DHTTP_ROOT_CA_DER;

/// Client certificate policy for DHTTP peer authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIdentityPolicy {
    /// Verify client certificates when peers provide them, but allow anonymous peers.
    Optional,
    /// Require peers to provide a certificate trusted by the DHTTP root store.
    Required,
}

/// Return the DHTTP ecosystem root certificate store.
///
/// The current embedded certificate is the transitional genmeta root CA. It is
/// expected to be replaced by the dhttp.net root CA when the ecosystem switches
/// domains.
pub fn dhttp_root_cert_store() -> &'static Arc<RootCertStore> {
    static STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
        let mut store = RootCertStore::empty();
        store
            .add(CertificateDer::from(DHTTP_ROOT_CA_DER))
            .expect("BUG: build script embedded an invalid DHTTP trust anchor");
        Arc::new(store)
    });
    &STORE
}

/// Build the default verifier for DHTTP clients validating server certificates.
pub fn dhttp_server_cert_verifier() -> Arc<WebPkiServerVerifier> {
    static VERIFIER: LazyLock<Arc<WebPkiServerVerifier>> = LazyLock::new(|| {
        WebPkiServerVerifier::builder(dhttp_root_cert_store().clone())
            .build()
            .expect("BUG: webpki server verifier built from fixed DHTTP roots")
    });
    VERIFIER.clone()
}

/// Build the default verifier for DHTTP servers validating client certificates.
pub fn dhttp_client_cert_verifier(policy: ClientIdentityPolicy) -> Arc<dyn ClientCertVerifier> {
    let builder = WebPkiClientVerifier::builder(dhttp_root_cert_store().clone());
    match policy {
        ClientIdentityPolicy::Optional => builder
            .allow_unauthenticated()
            .build()
            .expect("BUG: webpki client verifier built from fixed DHTTP roots"),
        ClientIdentityPolicy::Required => builder
            .build()
            .expect("BUG: webpki client verifier built from fixed DHTTP roots"),
    }
}

use crate::{Error, Result};
pub(crate) fn initialize() -> Result<()> {
    qtls::RootCerts::set([DHTTP_ROOT_CA_DER.to_vec().into()]).map_err(|source| Error::TlsConfig {
        source: Arc::new(source),
    })
}
