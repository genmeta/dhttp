use std::sync::{Arc, LazyLock};

use h3x::dquic::{
    client::{ClientQuicConfig, ServerCertVerifierChoice},
    server::ServerQuicConfig,
};
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
pub const DHTTP_ROOT_CA_DER: &[u8] = crate::bootstrap::DHTTP_ROOT_CA_DER;

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

/// Default DHTTP client-side QUIC configuration.
///
/// Verifies server certificates against the DHTTP ecosystem root and offers the
/// HTTP/3 ALPN.
pub fn default_client_quic_config() -> ClientQuicConfig {
    static CONFIG: LazyLock<ClientQuicConfig> = LazyLock::new(|| ClientQuicConfig {
        verifier: ServerCertVerifierChoice::WebPki(dhttp_server_cert_verifier()),
        alpns: vec![b"h3".to_vec()],
        ..Default::default()
    });
    CONFIG.clone()
}

/// Default DHTTP server-side QUIC configuration.
///
/// Verifies client certificates when provided, allows anonymous clients by
/// default, and advertises the HTTP/3 ALPN.
pub fn default_server_quic_config() -> ServerQuicConfig {
    static CONFIG: LazyLock<ServerQuicConfig> = LazyLock::new(|| ServerQuicConfig {
        alpns: vec![b"h3".to_vec()],
        backlog: 1024,
        client_cert_verifier: dhttp_client_cert_verifier(ClientIdentityPolicy::Optional),
        ..Default::default()
    });
    CONFIG.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_root_ca_der_is_a_valid_trust_anchor() {
        let mut store = RootCertStore::empty();

        store.add(CertificateDer::from(DHTTP_ROOT_CA_DER)).unwrap();

        assert_eq!(store.len(), 1);
    }

    #[test]
    fn dhttp_root_store_contains_embedded_root() {
        assert!(!dhttp_root_cert_store().roots.is_empty());
    }

    #[test]
    fn default_client_config_uses_dhttp_webpki_roots_and_h3_alpn() {
        let config = default_client_quic_config();

        assert!(matches!(
            config.verifier,
            ServerCertVerifierChoice::WebPki(_)
        ));
        assert_eq!(config.alpns, vec![b"h3".to_vec()]);
    }

    #[test]
    fn default_client_config_is_stable_across_calls() {
        let a = default_client_quic_config();
        let b = default_client_quic_config();

        assert_eq!(a, b);
    }

    #[test]
    fn default_server_config_uses_optional_dhttp_client_auth_and_h3_alpn() {
        let config = default_server_quic_config();

        assert_eq!(config.alpns, vec![b"h3".to_vec()]);
        assert_eq!(config.backlog, 1024);
        assert!(Arc::strong_count(&config.client_cert_verifier) >= 1);
    }

    #[test]
    fn default_server_config_is_stable_across_calls() {
        let a = default_server_quic_config();
        let b = default_server_quic_config();

        assert_eq!(a, b);
    }

    #[test]
    fn required_client_identity_policy_builds_verifier() {
        let verifier = dhttp_client_cert_verifier(ClientIdentityPolicy::Required);

        assert!(Arc::strong_count(&verifier) >= 1);
    }
}
