use std::{
    collections::VecDeque,
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

#[derive(Clone, Copy, Debug)]
enum WriteStep {
    Accept(usize),
    Error(io::ErrorKind),
    Zero,
}

struct ScriptedMaker {
    steps: std::sync::Mutex<VecDeque<WriteStep>>,
    write_calls: AtomicUsize,
    bytes: std::sync::Mutex<Vec<u8>>,
}

impl ScriptedMaker {
    fn new(steps: impl IntoIterator<Item = WriteStep>) -> Self {
        Self {
            steps: std::sync::Mutex::new(steps.into_iter().collect()),
            write_calls: AtomicUsize::new(0),
            bytes: std::sync::Mutex::new(Vec::new()),
        }
    }
}

struct ScriptedWriter<'a>(&'a ScriptedMaker);

impl Write for ScriptedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_calls.fetch_add(1, Ordering::SeqCst);
        let step = self
            .0
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(WriteStep::Accept(usize::MAX));

        match step {
            WriteStep::Accept(limit) => {
                let accepted = limit.min(bytes.len());
                self.0
                    .bytes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }
            WriteStep::Error(kind) => Err(io::Error::new(kind, "scripted write error")),
            WriteStep::Zero => Ok(0),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for ScriptedMaker {
    type Writer = ScriptedWriter<'writer>;

    fn make_writer(&'writer self) -> Self::Writer {
        ScriptedWriter(self)
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

#[test]
fn write_all_completes_across_partial_chunks() {
    let maker = ScriptedMaker::new([
        WriteStep::Accept(2),
        WriteStep::Accept(3),
        WriteStep::Accept(usize::MAX),
    ]);

    let outcome = MakeWriterSink::new(&maker)
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap();

    assert_eq!(outcome, DeliveryOutcome::Written);
    assert_eq!(maker.write_calls.load(Ordering::SeqCst), 3);
    assert_eq!(&*maker.bytes.lock().unwrap(), b"record\n");
}

#[test]
fn write_all_retries_interrupted_writes() {
    let maker = ScriptedMaker::new([
        WriteStep::Error(io::ErrorKind::Interrupted),
        WriteStep::Accept(usize::MAX),
    ]);

    let outcome = MakeWriterSink::new(&maker)
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap();

    assert_eq!(outcome, DeliveryOutcome::Written);
    assert_eq!(maker.write_calls.load(Ordering::SeqCst), 2);
    assert_eq!(&*maker.bytes.lock().unwrap(), b"record\n");
}

#[test]
fn partial_then_broken_pipe_keeps_source_and_accepted_prefix() {
    let maker = ScriptedMaker::new([
        WriteStep::Accept(3),
        WriteStep::Error(io::ErrorKind::BrokenPipe),
    ]);

    let error = MakeWriterSink::new(&maker)
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap_err();
    let DeliverRecordError::Write { source } = error else {
        panic!("partial write failure should remain a typed write error");
    };

    assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(&*maker.bytes.lock().unwrap(), b"rec");
}

#[test]
fn write_all_maps_zero_progress_to_write_zero() {
    let maker = ScriptedMaker::new([WriteStep::Zero]);

    let error = MakeWriterSink::new(&maker)
        .deliver(&"record", &AllowAll, &LiteralFormatter)
        .unwrap_err();
    let DeliverRecordError::Write { source } = error else {
        panic!("zero progress should remain a typed write error");
    };

    assert_eq!(source.kind(), io::ErrorKind::WriteZero);
    assert!(maker.bytes.lock().unwrap().is_empty());
}
