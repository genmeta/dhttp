#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChainKey {
    pub sequence: u32,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhttpSubjectKeyIdentifier {
    pub value: String,
    pub chain: CertificateChainKey,
    pub owner_hash: String,
}

impl From<dhttp::certificate::DhttpSubjectKeyIdentifier> for DhttpSubjectKeyIdentifier {
    fn from(value: dhttp::certificate::DhttpSubjectKeyIdentifier) -> Self {
        Self {
            value: value.to_string(),
            chain: CertificateChainKey {
                sequence: value.chain().sequence().get(),
                kind: value.chain().kind().as_str().to_owned(),
            },
            owner_hash: value.owner_hash().as_str().to_owned(),
        }
    }
}

pub fn parse_dhttp_subject_key_identifier_bytes(
    bytes: &[u8],
) -> Result<DhttpSubjectKeyIdentifier, crate::error::DhttpError> {
    dhttp::certificate::DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(bytes)
        .map(DhttpSubjectKeyIdentifier::from)
        .map_err(|error| {
            crate::error::DhttpError::from_error(
                "certificate.parse_dhttp_subject_key_identifier",
                error,
            )
        })
}

pub fn parse_dhttp_subject_key_identifier_str(
    value: &str,
) -> Result<DhttpSubjectKeyIdentifier, crate::error::DhttpError> {
    value
        .parse::<dhttp::certificate::DhttpSubjectKeyIdentifier>()
        .map(DhttpSubjectKeyIdentifier::from)
        .map_err(|error| {
            crate::error::DhttpError::from_error(
                "certificate.parse_dhttp_subject_key_identifier",
                error,
            )
        })
}
