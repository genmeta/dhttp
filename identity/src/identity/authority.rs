/// Local authority for DHTTP identity material.
///
/// Signatures use DHTTP's canonical key-to-signature-scheme policy instead of
/// accepting a caller-supplied scheme. The policy is:
///
/// - Ed25519 keys use [`SignatureScheme::ED25519`].
/// - ECDSA P-256 keys use [`SignatureScheme::ECDSA_NISTP256_SHA256`].
/// - ECDSA P-384 keys use [`SignatureScheme::ECDSA_NISTP384_SHA384`].
/// - RSA keys use [`SignatureScheme::RSA_PSS_SHA512`], matching the QUIC/TLS
///   RSA signing preference used by rustls.
///
/// Callers should treat `sign` and `verify` as DHTTP identity operations, not
/// as general-purpose cryptographic primitives with negotiable algorithms.
pub trait LocalAuthority: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>>;

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), data, signature);
        Box::pin(std::future::ready(result))
    }
}

/// Remote authority for DHTTP identity material.
///
/// Verification uses the same DHTTP canonical key-to-signature-scheme policy
/// as [`LocalAuthority`]. The policy is:
///
/// - Ed25519 keys use [`SignatureScheme::ED25519`].
/// - ECDSA P-256 keys use [`SignatureScheme::ECDSA_NISTP256_SHA256`].
/// - ECDSA P-384 keys use [`SignatureScheme::ECDSA_NISTP384_SHA384`].
/// - RSA keys use [`SignatureScheme::RSA_PSS_SHA512`], matching the QUIC/TLS
///   RSA signing preference used by rustls.
///
/// A remote authority does not carry an explicit signature scheme in its API;
/// the scheme is derived from the authority public key according to the
/// documented DHTTP policy.
pub trait RemoteAuthority: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), data, signature);
        Box::pin(std::future::ready(result))
    }
}

impl LocalAuthority for Identity {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        self.cert_chain()
    }

    fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
        let result = Identity::sign(self, data);
        Box::pin(std::future::ready(result))
    }
}

impl RemoteAuthority for Identity {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        self.cert_chain()
    }
}
