use std::{
    fmt,
    num::ParseIntError,
    str::{self, FromStr},
};

use snafu::{ResultExt, Snafu};

const DHTTP_SKI_FIELD_COUNT: usize = 3;
const OWNER_HASH_HEX_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateSequence(u32);

impl CertificateSequence {
    pub const MAX: u32 = i32::MAX as u32;

    pub fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidCertificateSequence {
    #[snafu(display("certificate sequence must be non-negative"))]
    Negative,
    #[snafu(display("certificate sequence exceeds supported database range"))]
    OutOfRange { value: u64 },
}

impl From<u8> for CertificateSequence {
    fn from(value: u8) -> Self {
        Self(value as u32)
    }
}

impl From<u16> for CertificateSequence {
    fn from(value: u16) -> Self {
        Self(value as u32)
    }
}

impl TryFrom<u32> for CertificateSequence {
    type Error = InvalidCertificateSequence;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::MAX {
            return invalid_certificate_sequence::OutOfRangeSnafu {
                value: value as u64,
            }
            .fail();
        }
        Ok(Self(value))
    }
}

impl TryFrom<i32> for CertificateSequence {
    type Error = InvalidCertificateSequence;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if value < 0 {
            return invalid_certificate_sequence::NegativeSnafu.fail();
        }
        Self::try_from(value as u32)
    }
}

impl TryFrom<u64> for CertificateSequence {
    type Error = InvalidCertificateSequence;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > Self::MAX as u64 {
            return invalid_certificate_sequence::OutOfRangeSnafu { value }.fail();
        }
        Ok(Self(value as u32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateUsage {
    ClientOnly,
    ClientAndServer,
}

impl CertificateUsage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientOnly => "client",
            Self::ClientAndServer => "client and server",
        }
    }

    pub fn kind_flag(self) -> &'static str {
        match self {
            Self::ClientOnly => "0",
            Self::ClientAndServer => "1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnerHash(String);

impl OwnerHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidOwnerHash {
    #[snafu(display("owner hash must be 64 lowercase hexadecimal characters"))]
    Invalid,
}

impl TryFrom<&str> for OwnerHash {
    type Error = InvalidOwnerHash;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == OWNER_HASH_HEX_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            invalid_owner_hash::InvalidSnafu.fail()
        }
    }
}

impl fmt::Display for OwnerHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateChainKey {
    sequence: CertificateSequence,
    usage: CertificateUsage,
}

impl CertificateChainKey {
    pub fn new(sequence: CertificateSequence, usage: CertificateUsage) -> Self {
        Self { sequence, usage }
    }

    pub fn sequence(&self) -> CertificateSequence {
        self.sequence
    }

    pub fn usage(&self) -> CertificateUsage {
        self.usage
    }
}

impl fmt::Display for CertificateChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.usage.as_str(), self.sequence.get())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhttpSubjectKeyIdentifier {
    chain: CertificateChainKey,
    owner_hash: OwnerHash,
}

impl DhttpSubjectKeyIdentifier {
    pub fn new(chain: CertificateChainKey, owner_hash: OwnerHash) -> Self {
        Self { chain, owner_hash }
    }

    pub fn try_from_subject_key_identifier_bytes(
        bytes: &[u8],
    ) -> Result<Self, InvalidDhttpSubjectKeyIdentifier> {
        let value =
            str::from_utf8(bytes).context(invalid_dhttp_subject_key_identifier::Utf8Snafu)?;
        value.parse()
    }

    pub fn chain(&self) -> &CertificateChainKey {
        &self.chain
    }

    pub fn owner_hash(&self) -> &OwnerHash {
        &self.owner_hash
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidDhttpSubjectKeyIdentifier {
    #[snafu(display("dhttp subject key identifier is not utf-8"))]
    Utf8 { source: str::Utf8Error },
    #[snafu(display(
        "dhttp subject key identifier must have sequence, kind, and owner hash fields"
    ))]
    FieldCount,
    #[snafu(display("dhttp subject key identifier sequence is invalid"))]
    Sequence { source: ParseIntError },
    #[snafu(display("dhttp subject key identifier sequence is out of range"))]
    SequenceRange { source: InvalidCertificateSequence },
    #[snafu(display("dhttp subject key identifier kind flag is invalid"))]
    KindFlag,
    #[snafu(display("dhttp subject key identifier owner hash is invalid"))]
    OwnerHash { source: InvalidOwnerHash },
}

impl FromStr for DhttpSubjectKeyIdentifier {
    type Err = InvalidDhttpSubjectKeyIdentifier;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let fields = value.split(':').collect::<Vec<_>>();
        if fields.len() != DHTTP_SKI_FIELD_COUNT {
            return invalid_dhttp_subject_key_identifier::FieldCountSnafu.fail();
        }
        let sequence = fields[0];
        let usage = fields[1];
        let owner_hash = fields[2];
        let sequence = sequence
            .parse::<u64>()
            .context(invalid_dhttp_subject_key_identifier::SequenceSnafu)?;
        let sequence = CertificateSequence::try_from(sequence)
            .context(invalid_dhttp_subject_key_identifier::SequenceRangeSnafu)?;
        let usage = match usage {
            "0" => CertificateUsage::ClientOnly,
            "1" => CertificateUsage::ClientAndServer,
            _ => return invalid_dhttp_subject_key_identifier::KindFlagSnafu.fail(),
        };
        let owner_hash = OwnerHash::try_from(owner_hash)
            .context(invalid_dhttp_subject_key_identifier::OwnerHashSnafu)?;

        Ok(Self::new(
            CertificateChainKey::new(sequence, usage),
            owner_hash,
        ))
    }
}

impl fmt::Display for DhttpSubjectKeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.chain.sequence().get(),
            self.chain.usage().kind_flag(),
            self.owner_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn certificate_sequence_accepts_database_compatible_range() {
        assert_eq!(CertificateSequence::from(7u8).get(), 7);
        assert_eq!(CertificateSequence::from(u16::MAX).get(), u16::MAX as u32);
        assert_eq!(CertificateSequence::try_from(0u32).unwrap().get(), 0);
        assert_eq!(
            CertificateSequence::try_from(i32::MAX as u32)
                .unwrap()
                .get(),
            i32::MAX as u32
        );
        assert_eq!(
            CertificateSequence::try_from(i32::MAX as u64)
                .unwrap()
                .get(),
            i32::MAX as u32
        );
    }

    #[test]
    fn certificate_sequence_rejects_values_outside_database_range() {
        assert!(matches!(
            CertificateSequence::try_from(-1),
            Err(InvalidCertificateSequence::Negative)
        ));
        assert!(matches!(
            CertificateSequence::try_from(i32::MAX as u32 + 1),
            Err(InvalidCertificateSequence::OutOfRange { .. })
        ));
        assert!(matches!(
            CertificateSequence::try_from(i32::MAX as u64 + 1),
            Err(InvalidCertificateSequence::OutOfRange { .. })
        ));
    }

    #[test]
    fn certificate_chain_key_displays_user_facing_label() {
        let primary = CertificateChainKey::new(
            CertificateSequence::try_from(0u32).unwrap(),
            CertificateUsage::ClientAndServer,
        );
        let secondary = CertificateChainKey::new(
            CertificateSequence::try_from(2u32).unwrap(),
            CertificateUsage::ClientOnly,
        );

        assert_eq!(primary.to_string(), "client and server:0");
        assert_eq!(secondary.to_string(), "client:2");
    }

    #[test]
    fn rejects_out_of_range_subject_key_identifier_sequence() {
        let error = format!("{}:0:{OWNER_HASH}", i32::MAX as u64 + 1)
            .parse::<DhttpSubjectKeyIdentifier>()
            .unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::SequenceRange { .. }
        ));
    }

    #[test]
    fn parses_canonical_dhttp_subject_key_identifier() {
        let ski = DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(
            format!("7:1:{OWNER_HASH}").as_bytes(),
        )
        .unwrap();

        assert_eq!(ski.chain().sequence().get(), 7);
        assert_eq!(ski.chain().usage(), CertificateUsage::ClientAndServer);
        assert_eq!(ski.owner_hash().as_str(), OWNER_HASH);
        assert_eq!(ski.to_string(), format!("7:1:{OWNER_HASH}"));
    }

    #[test]
    fn rejects_non_utf8_subject_key_identifier() {
        let error =
            DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(&[0xff]).unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::Utf8 { .. }
        ));
    }

    #[test]
    fn rejects_wrong_field_count() {
        let error = "0:1".parse::<DhttpSubjectKeyIdentifier>().unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::FieldCount
        ));
    }

    #[test]
    fn rejects_invalid_sequence() {
        let error = format!("-1:0:{OWNER_HASH}")
            .parse::<DhttpSubjectKeyIdentifier>()
            .unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::Sequence { .. }
        ));
    }

    #[test]
    fn rejects_invalid_kind_flag() {
        let error = format!("0:2:{OWNER_HASH}")
            .parse::<DhttpSubjectKeyIdentifier>()
            .unwrap_err();

        assert!(matches!(error, InvalidDhttpSubjectKeyIdentifier::KindFlag));
    }

    #[test]
    fn rejects_uppercase_owner_hash() {
        let error = format!("0:0:{}", OWNER_HASH.to_ascii_uppercase())
            .parse::<DhttpSubjectKeyIdentifier>()
            .unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::OwnerHash { .. }
        ));
    }

    #[test]
    fn rejects_short_owner_hash() {
        let error = "0:0:abc".parse::<DhttpSubjectKeyIdentifier>().unwrap_err();

        assert!(matches!(
            error,
            InvalidDhttpSubjectKeyIdentifier::OwnerHash { .. }
        ));
    }
}
