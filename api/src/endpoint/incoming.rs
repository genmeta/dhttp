use crate::stream::{ReadStream, WriteStream};

pub struct IncomingStream {
    stream_id: u64,
    read_stream: ReadStream,
    write_stream: WriteStream,
}

impl IncomingStream {
    pub(crate) fn new(request: dhttp::endpoint::server::UnresolvedRequest) -> Self {
        Self {
            stream_id: request.stream_id.into_inner(),
            read_stream: ReadStream::new(request.read_stream),
            write_stream: WriteStream::new(request.write_stream),
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn into_parts(self) -> (ReadStream, WriteStream) {
        (self.read_stream, self.write_stream)
    }
}
