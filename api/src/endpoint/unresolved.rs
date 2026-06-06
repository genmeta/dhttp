use crate::{
    authority::{LocalAuthority, RemoteAuthority},
    error::DhttpError,
    stream::{ReadStream, WriteStream},
};

pub type Result<T> = std::result::Result<T, DhttpError>;

pub struct UnresolvedRequest {
    stream_id: u64,
    reader: ReadStream,
    writer: WriteStream,
    local_authority: Option<LocalAuthority>,
    remote_authority: Option<RemoteAuthority>,
}

impl UnresolvedRequest {
    pub(crate) async fn new(request: dhttp::endpoint::server::UnresolvedRequest) -> Result<Self> {
        let dhttp::endpoint::server::UnresolvedRequest {
            stream_id,
            read_stream,
            write_stream,
            connection,
        } = request;

        let local_authority = connection
            .local_authority()
            .await
            .map_err(|error| DhttpError::from_error("unresolved_request.local_authority", error))?
            .map(LocalAuthority::new);
        let remote_authority = connection
            .remote_authority()
            .await
            .map_err(|error| DhttpError::from_error("unresolved_request.remote_authority", error))?
            .map(RemoteAuthority::new);

        Ok(Self {
            stream_id: stream_id.into_inner(),
            reader: ReadStream::new(read_stream),
            writer: WriteStream::new(write_stream),
            local_authority,
            remote_authority,
        })
    }

    pub(crate) async fn from_client_connection(
        connection: &crate::endpoint::connection::Connection,
        read_stream: ReadStream,
        write_stream: WriteStream,
    ) -> Result<Self> {
        let local_authority = connection.local_authority().await?;
        let remote_authority = connection.remote_authority().await?;
        Ok(Self {
            stream_id: 0,
            reader: read_stream,
            writer: write_stream,
            local_authority,
            remote_authority,
        })
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn local_authority(&self) -> Option<LocalAuthority> {
        self.local_authority.clone()
    }

    pub fn remote_authority(&self) -> Option<RemoteAuthority> {
        self.remote_authority.clone()
    }

    pub fn into_parts(self) -> (ReadStream, WriteStream) {
        (self.reader, self.writer)
    }
}
