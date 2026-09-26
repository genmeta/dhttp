pub fn sign_with_key(
    key: &(impl rustls::sign::SigningKey + ?Sized),
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    for scheme in canonical_signing_schemes(key.algorithm()) {
        if let Some(signer) = key.choose_scheme(&[*scheme]) {
            return signer.sign(data).context(sign_error::CryptoSnafu);
        }
    }

    sign_error::UnsupportedKeySnafu.fail()
}

pub fn verify_signature(
    spki: SubjectPublicKeyInfoDer,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let scheme = canonical_verification_scheme(spki.as_ref())?;
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return verify_error::UnsupportedKeySnafu.fail(),
    };

    let public_key = match SubjectPublicKeyInfo::from_der(&spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_) => return verify_error::UnsupportedKeySnafu.fail(),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}

fn canonical_signing_schemes(algorithm: rustls::SignatureAlgorithm) -> &'static [SignatureScheme] {
    match algorithm {
        rustls::SignatureAlgorithm::RSA => &[RSA_CANONICAL_SCHEME],
        rustls::SignatureAlgorithm::ECDSA => ECDSA_CANONICAL_SCHEMES,
        rustls::SignatureAlgorithm::ED25519 => &[ED25519_CANONICAL_SCHEME],
        _ => &[],
    }
}

fn canonical_verification_scheme(spki: &[u8]) -> Result<SignatureScheme, VerifyError> {
    let Ok((_remain, spki)) = SubjectPublicKeyInfo::from_der(spki) else {
        return verify_error::UnsupportedKeySnafu.fail();
    };

    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        return Ok(ED25519_CANONICAL_SCHEME);
    }

    if spki.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
        return Ok(RSA_CANONICAL_SCHEME);
    }

    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return verify_error::UnsupportedKeySnafu.fail();
    }

    let Some(curve) = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
    else {
        return verify_error::UnsupportedKeySnafu.fail();
    };

    if curve == OID_EC_P256 {
        Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
    } else if curve == OID_NIST_EC_P384 {
        Ok(SignatureScheme::ECDSA_NISTP384_SHA384)
    } else {
        verify_error::UnsupportedKeySnafu.fail()
    }
}
