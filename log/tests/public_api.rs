use dhttp_log::{
    FormatError, FormattedRecord, MAX_RECORD_LEN,
    access::{AccessLogRecord, DefaultAccessFormatter},
    cert::{CertificateLogRecord, DefaultCertificateFormatter},
};

#[test]
fn public_api_is_domain_and_builtin_formatter_only() {
    let access: fn(&AccessLogRecord) -> Result<FormattedRecord, FormatError> =
        DefaultAccessFormatter::format;
    let certificate: fn(&CertificateLogRecord) -> Result<FormattedRecord, FormatError> =
        DefaultCertificateFormatter::format;
    let _ = (access, certificate);
    assert_eq!(MAX_RECORD_LEN, 64 * 1024);
}
