use std::{error::Error, fmt};

use rustls_pemfile::{Item, read_one_from_slice};

pub const DEFAULT_BOOTSTRAP_URL: &str = "https://bootstrap.genmeta.net:20002";
pub const DEFAULT_ROOT_CA_PEM: &str = include_str!("root.crt");

pub fn env_or_default(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

pub fn bootstrap_authority(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|error| error.to_string())?;
    if url.scheme() != "https" {
        return Err("scheme must be https".to_owned());
    }
    if url.username() != "" || url.password().is_some() {
        return Err("credentials are not allowed".to_owned());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("path, query, and fragment are not allowed".to_owned());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "host is required".to_owned())?;
    let port = url
        .port()
        .ok_or_else(|| "an explicit port is required".to_owned())?;
    if matches!(url.host(), Some(url::Host::Ipv6(_))) {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

#[derive(Debug)]
pub enum RootCaError {
    DecodePem(rustls_pemfile::Error),
    MissingCertificate,
    UnexpectedPemItem,
    MultipleCertificates,
    InvalidX509(String),
    TrailingDerData,
}

impl fmt::Display for RootCaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecodePem(error) => write!(formatter, "failed to decode PEM: {error:?}"),
            Self::MissingCertificate => formatter.write_str("missing PEM CERTIFICATE block"),
            Self::UnexpectedPemItem => {
                formatter.write_str("PEM input contains a non-certificate item")
            }
            Self::MultipleCertificates => {
                formatter.write_str("PEM input contains multiple certificates")
            }
            Self::InvalidX509(error) => {
                write!(formatter, "certificate is not valid X.509 DER: {error}")
            }
            Self::TrailingDerData => formatter.write_str("certificate contains trailing DER data"),
        }
    }
}

impl Error for RootCaError {}

pub fn parse_root_ca_der(pem: &str) -> Result<Vec<u8>, RootCaError> {
    let mut remainder = pem.as_bytes();
    let mut certificate = None;

    while let Some((item, next)) = read_one_from_slice(remainder).map_err(RootCaError::DecodePem)? {
        remainder = next;
        let Item::X509Certificate(item) = item else {
            return Err(RootCaError::UnexpectedPemItem);
        };
        if certificate.replace(item).is_some() {
            return Err(RootCaError::MultipleCertificates);
        }
    }

    let certificate = certificate.ok_or(RootCaError::MissingCertificate)?;
    let (remainder, _) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| RootCaError::InvalidX509(error.to_string()))?;
    if !remainder.is_empty() {
        return Err(RootCaError::TrailingDerData);
    }

    Ok(certificate.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bootstrap_env_uses_genmeta_production_default() {
        let name = format!("__DHTTP_MISSING_BOOTSTRAP_{}", std::process::id());

        assert_eq!(
            env_or_default(&name, DEFAULT_BOOTSTRAP_URL),
            "https://bootstrap.genmeta.net:20002"
        );
    }

    #[test]
    fn bootstrap_url_produces_stun_authority() {
        assert_eq!(
            bootstrap_authority("https://bootstrap.genmeta.net:20002").as_deref(),
            Ok("bootstrap.genmeta.net:20002")
        );
    }

    #[test]
    fn bootstrap_url_requires_https_and_explicit_port() {
        assert!(bootstrap_authority("http://bootstrap.genmeta.net:20002").is_err());
        assert!(bootstrap_authority("https://bootstrap.genmeta.net").is_err());
    }

    #[test]
    fn default_root_ca_is_decoded_to_der() {
        let der = parse_root_ca_der(DEFAULT_ROOT_CA_PEM).unwrap();

        assert_eq!(der.first(), Some(&0x30));
        assert!(!der.starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn escaped_newlines_are_not_accepted_as_pem() {
        let escaped = DEFAULT_ROOT_CA_PEM.replace('\n', "\\n");

        assert!(parse_root_ca_der(&escaped).is_err());
    }

    #[test]
    fn crlf_root_ca_is_accepted_by_the_pem_parser() {
        let expected = parse_root_ca_der(DEFAULT_ROOT_CA_PEM).unwrap();
        let crlf = DEFAULT_ROOT_CA_PEM
            .replace("\r\n", "\n")
            .replace('\n', "\r\n");

        assert_eq!(parse_root_ca_der(&crlf).unwrap(), expected);
    }

    #[test]
    fn malformed_x509_certificate_is_rejected() {
        let pem = "-----BEGIN CERTIFICATE-----\nYm9keQ==\n-----END CERTIFICATE-----\n";

        assert!(matches!(
            parse_root_ca_der(pem),
            Err(RootCaError::InvalidX509(_))
        ));
    }

    #[test]
    fn multiple_certificates_are_rejected() {
        let pem = format!("{DEFAULT_ROOT_CA_PEM}{DEFAULT_ROOT_CA_PEM}");

        assert!(matches!(
            parse_root_ca_der(&pem),
            Err(RootCaError::MultipleCertificates)
        ));
    }

    #[test]
    fn non_certificate_pem_item_is_rejected() {
        let pem = DEFAULT_ROOT_CA_PEM.replace("CERTIFICATE", "PRIVATE KEY");

        assert!(matches!(
            parse_root_ca_der(&pem),
            Err(RootCaError::UnexpectedPemItem)
        ));
    }
}
