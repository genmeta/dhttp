use std::time::Duration;

use chrono::{FixedOffset, TimeZone};
use dhttp_log::{
    ClfTimestamp, CompactConvention, Decimal, ElementWriter, FormatElement, FormatElementError,
    MAX_RECORD_LEN, Optional, Quoted, RecordBuilder, SecondsMillis,
};

struct RawBytes<'a>(&'a [u8]);

impl FormatElement<CompactConvention> for RawBytes<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        output.bytes(self.0)
    }
}

fn one_element<E>(element: &E) -> Result<Vec<u8>, dhttp_log::FormatError>
where
    E: FormatElement<CompactConvention>,
{
    let mut builder = RecordBuilder::new();
    builder.element(&CompactConvention::default(), element)?;
    Ok(builder.finish()?.as_bytes().to_vec())
}

#[test]
fn finish_adds_exactly_one_line_feed() {
    assert_eq!(one_element(&RawBytes(b"record")).unwrap(), b"record\n");
}

#[test]
fn embedded_carriage_return_or_line_feed_is_rejected() {
    for bytes in [b"bad\rrecord".as_slice(), b"bad\nrecord".as_slice()] {
        assert!(one_element(&RawBytes(bytes)).is_err());
    }
}

#[test]
fn plain_rejects_unsafe_control_and_non_ascii() {
    for bytes in [b"bad\0value".as_slice(), b"bad\x7fvalue", b"bad\x80value"] {
        assert!(one_element(&RawBytes(bytes)).is_err());
    }
}

#[test]
fn quoted_escapes_quote_backslash_control_del_and_non_ascii() {
    let bytes = b"a\"\\\0\n\r\t\x1f\x7f\x80\xffz";

    assert_eq!(
        one_element(&Quoted(RawBytes(bytes))).unwrap(),
        b"\"a\\\"\\\\\\x00\\x0a\\x0d\\x09\\x1f\\x7f\\x80\\xffz\"\n"
    );
}

#[test]
fn optional_uses_missing_marker() {
    assert_eq!(
        one_element(&Optional::<RawBytes<'_>>(None)).unwrap(),
        b"-\n"
    );
    assert_eq!(
        one_element(&Quoted(Optional::<RawBytes<'_>>(None))).unwrap(),
        b"\"-\"\n"
    );
}

#[test]
fn quoted_composes_with_external_raw_bytes_and_optional() {
    assert_eq!(
        one_element(&Quoted(RawBytes(b"raw value"))).unwrap(),
        b"\"raw value\"\n"
    );
    assert_eq!(
        one_element(&Quoted(Optional(Some(RawBytes(b"raw value"))))).unwrap(),
        b"\"raw value\"\n"
    );
}

#[test]
fn clf_timestamp_uses_english_month_and_numeric_offset() {
    let offset = FixedOffset::east_opt(8 * 60 * 60).unwrap();
    let timestamp = offset.with_ymd_and_hms(2026, 7, 13, 16, 20, 31).unwrap();

    assert_eq!(
        one_element(&ClfTimestamp(timestamp)).unwrap(),
        b"[13/Jul/2026:16:20:31 +0800]\n"
    );
}

#[test]
fn decimal_formats_base_ten_integer() {
    assert_eq!(one_element(&Decimal(1432_u64)).unwrap(), b"1432\n");
}

#[test]
fn seconds_millis_uses_integer_rounding() {
    assert_eq!(
        one_element(&SecondsMillis(Duration::from_nanos(1_234_400_000))).unwrap(),
        b"1.234\n"
    );
    assert_eq!(
        one_element(&SecondsMillis(Duration::from_nanos(1_234_500_000))).unwrap(),
        b"1.235\n"
    );
}

#[test]
fn record_larger_than_64_kib_is_rejected() {
    let largest = vec![b'a'; MAX_RECORD_LEN - 1];
    assert_eq!(
        one_element(&RawBytes(&largest)).unwrap().len(),
        MAX_RECORD_LEN
    );

    let too_large = vec![b'a'; MAX_RECORD_LEN];
    assert!(one_element(&RawBytes(&too_large)).is_err());
}
