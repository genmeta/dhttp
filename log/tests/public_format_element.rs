use dhttp_log::{
    CompactConvention, ElementWriter, FormatElement, FormatElementError, RecordBuilder,
};

struct RequestId(u64);

impl FormatElement<CompactConvention> for RequestId {
    fn format_element(
        &self,
        _convention: &CompactConvention,
        output: &mut ElementWriter<'_>,
    ) -> Result<(), FormatElementError> {
        output.bytes(format!("request-{}", self.0).as_bytes())
    }
}

#[test]
fn external_type_can_implement_the_only_element_extension_point() {
    let mut builder = RecordBuilder::new();
    builder
        .element(&CompactConvention::default(), &RequestId(7))
        .expect("request id should format");

    let record = builder.finish().expect("record should finish");

    assert_eq!(record.as_bytes(), b"request-7\n");
}
