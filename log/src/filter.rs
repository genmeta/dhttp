/// Decides whether a typed domain record should be formatted and delivered.
pub trait FilterRecord<R>: Send + Sync {
    /// Returns whether `record` should proceed to formatting.
    fn enabled(&self, record: &R) -> bool;
}

/// A filter that enables every record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllowAll;

impl<R> FilterRecord<R> for AllowAll {
    fn enabled(&self, _record: &R) -> bool {
        true
    }
}
