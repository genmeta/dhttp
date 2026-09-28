use super::*;

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
