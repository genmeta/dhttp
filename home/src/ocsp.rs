//! Explicit OCSP preparation for an identity profile, shared by clients and services.
use crate::identity::IdentityProfile;

pub async fn load_or_refresh(
    profile: &IdentityProfile,
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    root_ca_der: &[u8],
) -> std::io::Result<Vec<u8>> {
    if let Ok(response) = profile.load_ocsp().await
        && qtls::validate_ocsp(&response, certificates, qtls::UnixTime::now()).is_ok()
    {
        return Ok(response);
    }
    let response = fetch_ocsp(certificates, root_ca_der).await?;
    let mut file = tempfile::NamedTempFile::new_in(profile.ssl_dir())?;
    use std::io::Write;
    file.write_all(&response)?;
    file.as_file().sync_all()?;
    file.persist(profile.ocsp_path())
        .map_err(|error| error.error)?;
    Ok(response)
}

async fn fetch_ocsp(
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    root_ca_der: &[u8],
) -> std::io::Result<Vec<u8>> {
    use der::{Decode, Encode};
    use sha1::{Digest, Sha1};
    use x509_parser::prelude::FromDer;
    let error = |error: String| std::io::Error::other(format!("OCSP: {error}"));
    let leaf = certificates
        .first()
        .ok_or_else(|| error("missing certificate".into()))?;
    let issuer = certificates
        .get(1)
        .ok_or_else(|| error("missing issuer certificate".into()))?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| error(e.to_string()))?;
    if !parsed.validity().is_valid() {
        return Err(error("certificate is outside its validity period".into()));
    }
    let url = parsed
        .extensions()
        .iter()
        .find_map(|extension| {
            let x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) =
                extension.parsed_extension()
            else {
                return None;
            };
            aia.accessdescs.iter().find_map(|access| {
                if access.access_method.to_id_string() != "1.3.6.1.5.5.7.48.1" {
                    return None;
                }
                match &access.access_location {
                    x509_parser::extensions::GeneralName::URI(uri) => Some((*uri).to_owned()),
                    _ => None,
                }
            })
        })
        .ok_or_else(|| error("certificate has no OCSP responder URI".into()))?;
    let leaf = x509_cert::Certificate::from_der(leaf.as_ref()).map_err(|e| error(e.to_string()))?;
    let issuer =
        x509_cert::Certificate::from_der(issuer.as_ref()).map_err(|e| error(e.to_string()))?;
    let request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            request_list: vec![x509_ocsp::Request {
                req_cert: x509_ocsp::CertId {
                    hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: "1.3.14.3.2.26"
                            .parse::<der::asn1::ObjectIdentifier>()
                            .map_err(|e| error(e.to_string()))?,
                        parameters: Some(der::asn1::Any::null()),
                    },
                    issuer_name_hash: der::asn1::OctetString::new(
                        Sha1::digest(
                            issuer
                                .tbs_certificate
                                .subject
                                .to_der()
                                .map_err(|e| error(e.to_string()))?,
                        )
                        .to_vec(),
                    )
                    .map_err(|e| error(e.to_string()))?,
                    issuer_key_hash: der::asn1::OctetString::new(
                        Sha1::digest(
                            issuer
                                .tbs_certificate
                                .subject_public_key_info
                                .subject_public_key
                                .raw_bytes(),
                        )
                        .to_vec(),
                    )
                    .map_err(|e| error(e.to_string()))?,
                    serial_number: leaf.tbs_certificate.serial_number,
                },
                single_request_extensions: None,
            }],
            ..Default::default()
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(|e| error(e.to_string()))?;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let root = reqwest::Certificate::from_der(root_ca_der).map_err(|e| error(e.to_string()))?;
        let client = reqwest::Client::builder()
            .tls_certs_merge([root])
            .redirect(reqwest::redirect::Policy::none())
            .https_only(false)
            .build()
            .map_err(|e| error(e.to_string()))?;
        let uri = reqwest::Url::parse(&url).map_err(|e| error(e.to_string()))?;
        if !matches!(uri.scheme(), "http" | "https") {
            return Err(error("unsupported responder scheme".into()));
        }
        let mut response = client
            .post(uri)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request)
            .send()
            .await
            .map_err(|e| error(e.to_string()))?;
        if !response.status().is_success() {
            return Err(error(format!("responder returned {}", response.status())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| error(e.to_string()))? {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(error("response exceeds 64KiB".into()));
            }
            body.extend_from_slice(&chunk);
        }
        qtls::validate_ocsp(&body, certificates, qtls::UnixTime::now())
            .map_err(|e| error(e.to_string()))?;
        Ok(body)
    })
    .await
    .map_err(|_| error("responder timed out after 15 seconds".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn malformed_cached_staple_is_not_accepted_or_overwritten_on_refresh_failure() {
        let dir = tempfile::tempdir().unwrap();
        let profile = IdentityProfile::try_from(dir.path().join("alice.pilot")).unwrap();
        tokio::fs::create_dir_all(profile.ssl_dir()).await.unwrap();
        tokio::fs::write(profile.ocsp_path(), b"invalid OCSP")
            .await
            .unwrap();
        let error = load_or_refresh(&profile, &[], &[]).await.unwrap_err();
        assert!(error.to_string().contains("missing certificate"));
        assert_eq!(
            tokio::fs::read(profile.ocsp_path()).await.unwrap(),
            b"invalid OCSP"
        );
    }
}
