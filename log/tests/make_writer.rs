use std::{
    error::Error as _,
    io::{self, Write},
    sync::atomic::{AtomicUsize, Ordering},
};

use dhttp_log::{
    AllowAll, CompactConvention, DeliverRecordError, DeliveryOutcome, ElementWriter, FilterRecord,
    FormatElement, FormatElementError, FormatError, FormatRecord, FormattedRecord, MakeWriterSink,
    RecordBuilder, RecordDelimiterError,
};
use tracing_subscriber::fmt::MakeWriter;

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

#[derive(Default)]
struct CountingMaker {
    acquires: AtomicUsize,
    write_calls: AtomicUsize,
    flushes: AtomicUsize,
    fail_write: bool,
    bytes: std::sync::Mutex<Vec<u8>>,
}

struct CountingWriter<'a>(&'a CountingMaker);

impl Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_calls.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_write {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "sentinel write"));
        }
        self.0.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CountingMaker {
    type Writer = CountingWriter<'writer>;

    fn make_writer(&'writer self) -> Self::Writer {
        self.acquires.fetch_add(1, Ordering::SeqCst);
        CountingWriter(self)
    }
}

struct DenyAll;

impl<R> FilterRecord<R> for DenyAll {
    fn enabled(&self, _record: &R) -> bool {
        false
    }
}

struct LiteralFormatter;

impl FormatRecord<&str> for LiteralFormatter {
    fn format_record(&self, record: &&str) -> Result<FormattedRecord, FormatError> {
        let mut builder = RecordBuilder::new();
        builder.element(&CompactConvention::default(), &RawBytes(record.as_bytes()))?;
        builder.finish()
    }
}

struct ErrorFormatter;

impl FormatRecord<&str> for ErrorFormatter {
    fn format_record(&self, _record: &&str) -> Result<FormattedRecord, FormatError> {
        let mut builder = RecordBuilder::new();
        builder.element(&CompactConvention::default(), &RawBytes(b"bad\nrecord"))?;
        builder.finish()
    }
}

#[test]
fn deny_all_is_filtered_without_acquiring_writer() {
    let maker = CountingMaker::default();
    let sink = MakeWriterSink::new(&maker);

    let outcome = sink.deliver(&"record", &DenyAll, &ErrorFormatter).unwrap();

    assert_eq!(outcome, DeliveryOutcome::Filtered);
    assert_eq!(maker.acquires.load(Ordering::SeqCst), 0);
}

#[test]
fn allow_all_writes_once_without_flushing() {
    let maker = CountingMaker::default();
    let sink = MakeWriterSink::new(&maker);

    let outcome = sink
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap();

    assert_eq!(outcome, DeliveryOutcome::Written);
    assert_eq!(maker.acquires.load(Ordering::SeqCst), 1);
    assert_eq!(maker.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(&*maker.bytes.lock().unwrap(), b"record\n");
    assert_eq!(maker.flushes.load(Ordering::SeqCst), 0);
}

#[test]
fn format_error_does_not_acquire_writer() {
    let maker = CountingMaker::default();
    let sink = MakeWriterSink::new(&maker);

    assert!(matches!(
        sink.deliver(&"record", &AllowAll, &ErrorFormatter),
        Err(DeliverRecordError::Format {
            source: FormatError::Element {
                source: FormatElementError::RecordDelimiter {
                    source: RecordDelimiterError::LineFeed,
                },
            },
        })
    ));
    assert_eq!(maker.acquires.load(Ordering::SeqCst), 0);
}

#[test]
fn immediate_write_error_keeps_io_source() {
    let maker = CountingMaker {
        fail_write: true,
        ..CountingMaker::default()
    };
    let sink = MakeWriterSink::new(&maker);

    let error = sink
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap_err();
    let source = error.source().expect("write error should keep its source");
    let source = source
        .downcast_ref::<io::Error>()
        .expect("source should remain an io::Error");

    assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(source.to_string(), "sentinel write");
    assert_eq!(maker.acquires.load(Ordering::SeqCst), 1);
}
