pub fn extract_subject_key_identifier<'a>(
    cert_chain: &'a [CertificateDer<'a>],
) -> Result<Option<&'a [u8]>, ExtractSubjectKeyIdentifierError> {
    let leaf = cert_chain
        .first()
        .context(extract_subject_key_identifier_error::EmptyCertificateChainSnafu)?;
    let (_remain, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf)
        .context(extract_subject_key_identifier_error::ParseCertificateSnafu)?;

    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            return Ok(Some(identifier.0));
        }
        if extension.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
            return extract_subject_key_identifier_error::ParseExtensionSnafu.fail();
        }
    }

    Ok(None)
}

pub fn extract_dhttp_subject_key_identifier(
    cert_chain: &[CertificateDer<'_>],
) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
    let ski = extract_subject_key_identifier(cert_chain)?
        .context(extract_dhttp_subject_key_identifier_error::MissingSubjectKeyIdentifierSnafu)?;
    DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(ski)
        .context(extract_dhttp_subject_key_identifier_error::InvalidDhttpSubjectKeyIdentifierSnafu)
}

mod private {
    pub trait Sealed {}

    impl<T: ?Sized> Sealed for T {}
}

pub trait LocalAuthorityCertificateExt: private::Sealed {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError>;

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError>;
}

impl<T: ?Sized + LocalAuthority> LocalAuthorityCertificateExt for T {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError> {
        extract_subject_key_identifier(self.cert_chain())
    }

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
        extract_dhttp_subject_key_identifier(self.cert_chain())
    }
}

pub trait RemoteAuthorityCertificateExt: private::Sealed {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError>;

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError>;
}

impl<T: ?Sized + RemoteAuthority> RemoteAuthorityCertificateExt for T {
    fn subject_key_identifier(&self) -> Result<Option<&[u8]>, ExtractSubjectKeyIdentifierError> {
        extract_subject_key_identifier(self.cert_chain())
    }

    fn dhttp_subject_key_identifier(
        &self,
    ) -> Result<DhttpSubjectKeyIdentifier, ExtractDhttpSubjectKeyIdentifierError> {
        extract_dhttp_subject_key_identifier(self.cert_chain())
    }
}

pub fn extract_public_key<'d>(cert_chain: &'d [CertificateDer<'d>]) -> SubjectPublicKeyInfoDer<'d> {
    match x509_parser::certificate::X509Certificate::from_der(&cert_chain[0]) {
        Ok((_remain, certificate)) => {
            let spki = certificate.public_key().raw;
            spki.to_owned().into()
        }
        Err(_) if cert_chain.len() == 1 => cert_chain[0].as_ref().into(),
        Err(_) => unreachable!("rustls returned an invalid peer_certificates"),
    }
}
