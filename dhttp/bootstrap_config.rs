use std::{error::Error, fmt};

use rustls_pemfile::{Item, read_one_from_slice};

pub const DEFAULT_ROOT_CA_PEM: &str = include_str!("root.crt");

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
#[path = "tests/unit/bootstrap_config.rs"]
mod tests;
