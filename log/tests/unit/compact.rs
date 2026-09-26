use super::{
    ClfTimestamp, CompactConvention, Decimal, ElementWriter, FormatElement, Optional, Quoted,
};
use crate::{FormatError, MAX_RECORD_LEN, record::RecordBuilder};
use chrono::{FixedOffset, TimeZone};

struct RawBytes<'a>(&'a [u8]);

impl FormatElement<CompactConvention> for RawBytes<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.0)
    }
}

fn one_element<E>(element: &E) -> Result<Vec<u8>, FormatError>
where
    E: FormatElement<CompactConvention>,
{
    let mut builder = RecordBuilder::new();
    builder.element(&CompactConvention::default(), element)?;
    Ok(builder.finish()?.as_bytes().to_vec())
}

#[test]
fn finish_adds_exactly_one_delimiter_and_rejects_embedded_newlines() {
    let mut builder = RecordBuilder::new();
    builder.literal(b"value").unwrap();
    assert_eq!(builder.finish().unwrap().as_bytes(), b"value\n");

    let mut builder = RecordBuilder::new();
    assert!(matches!(
        builder.literal(b"value\n"),
        Err(FormatError::LineFeed)
    ));
}

#[test]
fn embedded_carriage_return_or_line_feed_is_rejected() {
    for (bytes, delimiter) in [
        (b"bad\rrecord".as_slice(), FormatError::CarriageReturn),
        (b"bad\nrecord".as_slice(), FormatError::LineFeed),
    ] {
        assert!(matches!(
            one_element(&RawBytes(bytes)),
            Err(error) if error == delimiter
        ));
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
fn nested_quoted_is_rejected_without_leaving_partial_bytes() {
    let convention = CompactConvention::default();
    let mut builder = RecordBuilder::new();
    builder.literal(b"before ").unwrap();

    assert!(matches!(
        builder.element(&convention, &Quoted(Quoted(RawBytes(b"nested")))),
        Err(FormatError::NestedQuoted)
    ));

    builder
        .element(&convention, &RawBytes(b"after"))
        .expect("builder should remain usable after rejecting nested quoting");
    assert_eq!(builder.finish().unwrap().as_bytes(), b"before after\n");
}

struct RequestLine<'a> {
    method: &'a [u8],
    target: &'a [u8],
    version: &'a [u8],
}

impl FormatElement<CompactConvention> for RequestLine<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        output.bytes(self.method)?;
        output.bytes(b" ")?;
        output.bytes(self.target)?;
        output.bytes(b" ")?;
        output.bytes(self.version)
    }
}

#[test]
fn composite_request_line_formats_through_quoted_wrapper() {
    let request_line = RequestLine {
        method: b"GET",
        target: b"/assets/a.css",
        version: b"HTTP/3",
    };

    assert_eq!(
        one_element(&Quoted(request_line)).unwrap(),
        b"\"GET /assets/a.css HTTP/3\"\n"
    );
}

struct Sha256Fingerprint<'a>(&'a [u8]);

impl FormatElement<CompactConvention> for Sha256Fingerprint<'_> {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        output.bytes(b"sha256:")?;
        for byte in self.0 {
            output.bytes(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])?;
        }
        Ok(())
    }
}

#[test]
fn canonical_fingerprint_formats_through_optional_and_quoted_wrappers() {
    assert_eq!(
        one_element(&Quoted(Optional(Some(Sha256Fingerprint(&[
            0x01, 0x23, 0xab, 0xcd,
        ])))))
        .unwrap(),
        b"\"sha256:0123abcd\"\n"
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
fn record_larger_than_64_kib_is_rejected() {
    let largest = vec![b'a'; MAX_RECORD_LEN - 1];
    assert_eq!(
        one_element(&RawBytes(&largest)).unwrap().len(),
        MAX_RECORD_LEN
    );

    let too_large = vec![b'a'; MAX_RECORD_LEN];
    assert!(one_element(&RawBytes(&too_large)).is_err());
}
