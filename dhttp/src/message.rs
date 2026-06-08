use std::{borrow::Cow, ops::ControlFlow};

use bytes::{Buf, Bytes, BytesMut};
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{InvalidHeaderName, InvalidHeaderValue},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::{ResultExt, Snafu};

use crate::h3x::{
    buflist::{BufList, BuflistCursor},
    connection,
    dhttp::message::{MessageReader, MessageStreamError, MessageWriter},
    error::{Code, H3FrameUnexpected, H3MessageError},
    qpack::field::{
        FieldLine, FieldSection, MalformedHeaderSection, Protocol, malformed_header_section,
    },
};

/// Buffered DHTTP message body payload.
pub type Body = BufList;

/// Converts common byte/string payload types into a buffered DHTTP body.
pub trait IntoBody {
    fn into_body(self) -> Body;
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IntoAuthorityError {
    #[snafu(display("failed to parse authority"))]
    Parse { source: http::uri::InvalidUri },
    #[snafu(display("failed to expand dhttp shorthand in authority"))]
    Expand {
        source: crate::name::ExpandAuthorityError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IntoUriError {
    #[snafu(display("failed to parse uri"))]
    Parse { source: http::uri::InvalidUri },
    #[snafu(display("failed to normalize uri authority"))]
    Authority { source: IntoAuthorityError },
    #[snafu(display("failed to reconstruct uri"))]
    Reconstruct { source: http::uri::InvalidUriParts },
}

/// Converts common authority input types into a normalized [`http::uri::Authority`].
pub trait IntoAuthority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError>;
}

/// Converts common URI input types into a normalized [`http::Uri`].
pub trait IntoUri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError>;
}

impl IntoAuthority for Authority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        crate::name::DhttpName::expand_authority_with_base(self_name, self)
            .context(into_authority_error::ExpandSnafu)
    }
}

impl IntoAuthority for &Authority {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        self.clone().into_authority(self_name)
    }
}

impl IntoAuthority for &str {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        Authority::try_from(self)
            .context(into_authority_error::ParseSnafu)?
            .into_authority(self_name)
    }
}

impl IntoAuthority for String {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        Authority::try_from(self)
            .context(into_authority_error::ParseSnafu)?
            .into_authority(self_name)
    }
}

impl IntoAuthority for &String {
    fn into_authority(
        self,
        self_name: Option<&crate::name::DhttpName<'_>>,
    ) -> Result<Authority, IntoAuthorityError> {
        self.as_str().into_authority(self_name)
    }
}

impl IntoUri for Uri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        let mut parts = self.into_parts();
        if let Some(authority) = parts.authority {
            parts.authority = Some(
                authority
                    .into_authority(self_name)
                    .context(into_uri_error::AuthoritySnafu)?,
            );
        }
        Uri::from_parts(parts).context(into_uri_error::ReconstructSnafu)
    }
}

impl IntoUri for &Uri {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        self.clone().into_uri(self_name)
    }
}

impl IntoUri for &str {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for String {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for &String {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        self.as_str().into_uri(self_name)
    }
}

impl IntoUri for &[u8] {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

impl IntoUri for Vec<u8> {
    fn into_uri(self, self_name: Option<&crate::name::DhttpName<'_>>) -> Result<Uri, IntoUriError> {
        Uri::try_from(self)
            .context(into_uri_error::ParseSnafu)?
            .into_uri(self_name)
    }
}

fn body_from_buf(buf: impl Buf) -> Body {
    let mut body = Body::new();
    body.write(buf);
    body
}

impl IntoBody for Body {
    fn into_body(self) -> Body {
        self
    }
}

impl IntoBody for Bytes {
    fn into_body(self) -> Body {
        body_from_buf(self)
    }
}

impl IntoBody for BytesMut {
    fn into_body(self) -> Body {
        body_from_buf(self)
    }
}

impl IntoBody for Vec<u8> {
    fn into_body(self) -> Body {
        body_from_buf(Bytes::from(self))
    }
}

impl IntoBody for String {
    fn into_body(self) -> Body {
        body_from_buf(Bytes::from(self))
    }
}

impl IntoBody for () {
    fn into_body(self) -> Body {
        Body::new()
    }
}

impl<'a> IntoBody for Cow<'a, str> {
    fn into_body(self) -> Body {
        match self {
            Cow::Borrowed(content) => content.into_body(),
            Cow::Owned(content) => content.into_body(),
        }
    }
}

impl<'a> IntoBody for Cow<'a, [u8]> {
    fn into_body(self) -> Body {
        match self {
            Cow::Borrowed(content) => content.into_body(),
            Cow::Owned(content) => content.into_body(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> IntoBody for &T {
    fn into_body(self) -> Body {
        body_from_buf(Bytes::copy_from_slice(self.as_ref()))
    }
}

fn header_map_to_field_lines(headers: &HeaderMap) -> impl Iterator<Item = FieldLine> + '_ {
    headers.iter().map(|(name, value)| FieldLine {
        name: Bytes::from_owner(name.clone()),
        value: Bytes::from_owner(value.clone()),
    })
}

pub trait BeMessageHeader: Clone {
    type Iter<'a>: Iterator<Item = FieldLine> + 'a
    where
        Self: 'a;

    fn header_map(&self) -> &HeaderMap;

    fn iter(&self) -> Self::Iter<'_>;

    fn is_interim(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    method: Method,
    scheme: Scheme,
    authority: Authority,
    path: PathAndQuery,
    protocol: Option<Protocol>,
    headers: HeaderMap,
}

impl RequestHeader {
    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn path(&self) -> &PathAndQuery {
        &self.path
    }

    pub fn protocol(&self) -> Option<&Protocol> {
        self.protocol.as_ref()
    }

    pub fn uri(&self) -> Uri {
        let mut parts = http::uri::Parts::default();
        parts.scheme = Some(self.scheme.clone());
        parts.authority = Some(self.authority.clone());
        parts.path_and_query = Some(self.path.clone());
        Uri::from_parts(parts).expect("valid URI parts from request header")
    }

    pub fn header_map(&self) -> &HeaderMap {
        &self.headers
    }

    fn field_lines(&self) -> Vec<FieldLine> {
        let mut fields = Vec::with_capacity(self.headers.len() + 5);
        fields.push(self.method.clone().into());
        if let Some(protocol) = self.protocol.clone() {
            fields.push(protocol.into());
        }
        fields.push(self.scheme.clone().into());
        fields.push(self.authority.clone().into());
        fields.push(self.path.clone().into());
        fields.extend(header_map_to_field_lines(&self.headers));
        fields
    }
}

impl TryFrom<FieldSection> for RequestHeader {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        value.check_pseudo()?;
        if value.is_response_header() {
            return Err(MalformedHeaderSection::ResponsePseudoHeaderInRequest);
        }
        if value.is_trailer() {
            return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
        }

        let method = value.method();
        let Some(scheme) = value.scheme() else {
            return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
        };
        let Some(authority) = value.authority() else {
            return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
        };
        let Some(path) = value.path() else {
            return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
        };
        let protocol = value.protocol();
        let headers = value.into_header_map();

        Ok(Self {
            method,
            scheme,
            authority,
            path,
            protocol,
            headers,
        })
    }
}

impl BeMessageHeader for RequestHeader {
    type Iter<'a> = std::vec::IntoIter<FieldLine>;

    fn header_map(&self) -> &HeaderMap {
        &self.headers
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.field_lines().into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    status: StatusCode,
    headers: HeaderMap,
}

impl ResponseHeader {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    pub fn header_map(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header_map_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn is_interim(&self) -> bool {
        self.status.is_informational()
    }

    fn field_lines(&self) -> Vec<FieldLine> {
        let mut fields = Vec::with_capacity(self.headers.len() + 1);
        fields.push(self.status.into());
        fields.extend(header_map_to_field_lines(&self.headers));
        fields
    }
}

impl Default for ResponseHeader {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }
    }
}

impl TryFrom<FieldSection> for ResponseHeader {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        value.check_pseudo()?;
        if value.is_request_header() {
            return Err(MalformedHeaderSection::RequestPseudoHeaderInResponse);
        }
        if value.is_trailer() {
            return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
        }
        let status = value.status();
        let headers = value.into_header_map();
        Ok(Self { status, headers })
    }
}

impl BeMessageHeader for ResponseHeader {
    type Iter<'a> = std::vec::IntoIter<FieldLine>;

    fn header_map(&self) -> &HeaderMap {
        &self.headers
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.field_lines().into_iter()
    }

    fn is_interim(&self) -> bool {
        ResponseHeader::is_interim(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Trailer {
    headers: HeaderMap,
}

impl Trailer {
    pub fn new(headers: HeaderMap) -> Self {
        Self { headers }
    }

    pub fn header_map(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header_map_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn into_header_map(self) -> HeaderMap {
        self.headers
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    pub fn iter(&self) -> std::vec::IntoIter<FieldLine> {
        header_map_to_field_lines(&self.headers)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl TryFrom<FieldSection> for Trailer {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        if !value.is_trailer() {
            return Err(MalformedHeaderSection::PseudoHeaderInTrailer);
        }
        Ok(Self {
            headers: value.into_header_map(),
        })
    }
}

/// Message body transfer state.
#[derive(Debug, Clone)]
pub enum BodyState {
    Pending,
    Streaming { count: u64 },
    Buffered { buflist: BuflistCursor },
}

impl BodyState {
    fn reset_buffer_cursor(&mut self) {
        if let BodyState::Buffered { buflist } = self {
            buflist.reset();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageStage {
    /// Receiving/Sending header section, including interim response headers
    Header = 0,
    /// Receiving/Sending message body
    Body = 1,
    /// Receiving/Sending trailer section
    Trailer = 2,
    /// Message is completely sent/received
    Complete = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageWriteGoal {
    Header,
    Body,
    Complete,
}

pub type MessageWriteFlow = ControlFlow<Result<(), MessageStreamError>, ()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReadAction {
    Ready,
    Complete,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MutateHeaderError {
    #[snafu(display("cannot modify header section after it has been sent"))]
    AlreadySent,
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum EnsureStreamingBodyError {
    #[snafu(display("message body is already complete"))]
    BodyAlreadyComplete,
    #[snafu(display("streaming body operation cannot be performed on buffered body"))]
    BufferedBody,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EnsureBufferedBodyError {
    #[snafu(display("message body is already complete"))]
    BodyAlreadyComplete,
    #[snafu(display("buffered body operation cannot be performed on streaming body"))]
    StreamingBody,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PrepareStreamingBodyReadError {
    #[snafu(display("failed to select streaming body mode"))]
    BodyMode { source: EnsureStreamingBodyError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PrepareBufferedBodyReadError {
    #[snafu(display("failed to select buffered body mode"))]
    BodyMode { source: EnsureBufferedBodyError },
    #[snafu(display("buffered body operation cannot be performed on streaming body"))]
    StreamingBody,
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum PrepareStreamingBodyWriteError {
    #[snafu(display("message body is already complete"))]
    BodyAlreadyComplete,
    #[snafu(display("failed to select streaming body mode"))]
    BodyMode { source: EnsureStreamingBodyError },
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module)]
pub enum CommitStreamingBodyWriteError {
    #[snafu(display("failed to select streaming body mode"))]
    BodyMode { source: EnsureStreamingBodyError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadStreamingBodyError {
    #[snafu(display("failed to prepare streaming body read"))]
    Prepare {
        source: PrepareStreamingBodyReadError,
    },
    #[snafu(display("message stream error"))]
    Stream { source: MessageStreamError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadBufferedBodyError {
    #[snafu(display("failed to prepare buffered body read"))]
    Prepare {
        source: PrepareBufferedBodyReadError,
    },
    #[snafu(display("message stream error"))]
    Stream { source: MessageStreamError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadTrailersError {
    #[snafu(display("failed to read buffered body before trailers"))]
    Body { source: ReadBufferedBodyError },
    #[snafu(display("cannot read trailers after streaming body was selected"))]
    StreamingBody,
    #[snafu(display("message stream error"))]
    Stream { source: MessageStreamError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadAllError {
    #[snafu(display("failed to read message header"))]
    Header { source: MessageStreamError },
    #[snafu(display("failed to read message body"))]
    Body { source: ReadBufferedBodyError },
    #[snafu(display("failed to read message trailers"))]
    Trailers { source: ReadTrailersError },
}

#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum WriteStreamingBodyError {
    #[snafu(display("failed to prepare streaming body write"))]
    Prepare {
        source: PrepareStreamingBodyWriteError,
    },
    #[snafu(display("message stream error"))]
    Stream { source: MessageStreamError },
    #[snafu(display("failed to commit streaming body write"))]
    Commit {
        source: CommitStreamingBodyWriteError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteBufferedBodyError {
    #[snafu(display("failed to select buffered body mode"))]
    BodyMode { source: EnsureBufferedBodyError },
    #[snafu(display("message stream error"))]
    Stream { source: MessageStreamError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SetBodyError {
    #[snafu(display("cannot replace body content while sending"))]
    BodyReplacementDuringSend,
    #[snafu(display("cannot set body after body is complete"))]
    BodyAlreadyComplete,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MutateTrailersError {
    #[snafu(display("cannot modify trailer section after it has been sent"))]
    AlreadySent,
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum MessageOperationError {
    #[snafu(transparent)]
    MutateHeader { source: MutateHeaderError },
    #[snafu(transparent)]
    EnsureStreamingBody { source: EnsureStreamingBodyError },
    #[snafu(transparent)]
    EnsureBufferedBody { source: EnsureBufferedBodyError },
    #[snafu(transparent)]
    SetBody { source: SetBodyError },
    #[snafu(transparent)]
    MutateTrailers { source: MutateTrailersError },
    #[snafu(transparent)]
    PrepareStreamingBodyWrite {
        source: PrepareStreamingBodyWriteError,
    },
    #[snafu(transparent)]
    CommitStreamingBodyWrite {
        source: CommitStreamingBodyWriteError,
    },
    #[snafu(display("cannot send malformed pseudo header section"))]
    MalformedPseudoHeader { source: MalformedHeaderSection },
    #[snafu(display("cannot set body or trailer for interim (1xx) response"))]
    BodyOrTrailerOnInterimResponse,
    #[snafu(display("cannot close response stream without sending a final response"))]
    FinalResponseRequired,
}

impl From<MalformedHeaderSection> for MessageOperationError {
    fn from(source: MalformedHeaderSection) -> Self {
        MessageOperationError::MalformedPseudoHeader { source }
    }
}

#[derive(Debug, Clone)]
pub struct Message<H: BeMessageHeader> {
    header: H,
    body: BodyState,
    trailer: Trailer,
    stage: MessageStage,
}

pub type RequestMessage = Message<RequestHeader>;
pub type ResponseMessage = Message<ResponseHeader>;

#[derive(Debug, Snafu)]
pub enum InvalidHeader {
    #[snafu(transparent)]
    Name { source: InvalidHeaderName },
    #[snafu(transparent)]
    Value { source: InvalidHeaderValue },
}

impl<H: BeMessageHeader> Message<H> {
    pub fn new(header: H) -> Self {
        Self {
            header,
            body: BodyState::Pending,
            trailer: Trailer::default(),
            stage: MessageStage::Header,
        }
    }

    pub(crate) fn with_parts(header: H, body: BodyState, trailer: Trailer) -> Self {
        Self {
            header,
            body,
            trailer,
            stage: MessageStage::Header,
        }
    }

    pub fn header(&self) -> &H {
        &self.header
    }

    fn header_mut_checked(&mut self) -> Result<&mut H, MutateHeaderError> {
        if self.stage > MessageStage::Header {
            return Err(MutateHeaderError::AlreadySent);
        }
        Ok(&mut self.header)
    }

    pub fn is_interim_response(&self) -> bool {
        self.header.is_interim()
    }

    pub fn streaming_body(&mut self) -> Result<&mut u64, EnsureStreamingBodyError> {
        if self.stage > MessageStage::Body {
            return Err(EnsureStreamingBodyError::BodyAlreadyComplete);
        }

        match &self.body {
            BodyState::Pending => self.body = BodyState::Streaming { count: 0 },
            BodyState::Streaming { .. } => {}
            BodyState::Buffered { .. } => {
                return Err(EnsureStreamingBodyError::BufferedBody);
            }
        }
        match &mut self.body {
            BodyState::Pending => unreachable!(),
            BodyState::Streaming { count } => Ok(count),
            BodyState::Buffered { .. } => unreachable!(),
        }
    }

    pub fn buffered_body(&mut self) -> Result<&mut BuflistCursor, EnsureBufferedBodyError> {
        if self.stage > MessageStage::Body {
            return Err(EnsureBufferedBodyError::BodyAlreadyComplete);
        }

        match &self.body {
            BodyState::Pending => {
                self.body = BodyState::Buffered {
                    buflist: BuflistCursor::new(BufList::new()),
                };
            }
            BodyState::Buffered { .. } => {}
            BodyState::Streaming { .. } => {
                return Err(EnsureBufferedBodyError::StreamingBody);
            }
        }
        match &mut self.body {
            BodyState::Pending => unreachable!(),
            BodyState::Streaming { .. } => unreachable!(),
            BodyState::Buffered { buflist } => Ok(buflist),
        }
    }

    fn prepare_streaming_body_read(
        &mut self,
    ) -> Result<BodyReadAction, PrepareStreamingBodyReadError> {
        match self.stage {
            MessageStage::Header | MessageStage::Body => {
                self.streaming_body()
                    .context(prepare_streaming_body_read_error::BodyModeSnafu)?;
                Ok(BodyReadAction::Ready)
            }
            MessageStage::Trailer | MessageStage::Complete => Ok(BodyReadAction::Complete),
        }
    }

    fn prepare_buffered_body_read(
        &mut self,
    ) -> Result<BodyReadAction, PrepareBufferedBodyReadError> {
        match self.stage {
            MessageStage::Header | MessageStage::Body => {
                self.buffered_body()
                    .context(prepare_buffered_body_read_error::BodyModeSnafu)?;
                Ok(BodyReadAction::Ready)
            }
            MessageStage::Trailer | MessageStage::Complete => {
                match &self.body {
                    BodyState::Pending => {
                        self.body = BodyState::Buffered {
                            buflist: BuflistCursor::new(BufList::new()),
                        };
                    }
                    BodyState::Buffered { .. } => {}
                    BodyState::Streaming { .. } => {
                        return Err(PrepareBufferedBodyReadError::StreamingBody);
                    }
                }
                Ok(BodyReadAction::Complete)
            }
        }
    }

    pub(crate) fn prepare_streaming_body_write(
        &mut self,
        content: impl IntoBody,
    ) -> Result<PreparedStreamingBody, PrepareStreamingBodyWriteError> {
        let content = content.into_body();
        let body_len = content.remaining() as u64;

        match self.stage {
            MessageStage::Header | MessageStage::Body => {
                self.streaming_body()
                    .context(prepare_streaming_body_write_error::BodyModeSnafu)?;
                Ok(PreparedStreamingBody {
                    header: prepare_message_write_next_part_to(self, MessageWriteGoal::Header),
                    content,
                    body_len,
                })
            }
            MessageStage::Trailer | MessageStage::Complete => {
                Err(PrepareStreamingBodyWriteError::BodyAlreadyComplete)
            }
        }
    }

    pub(crate) fn commit_streaming_body_write(
        &mut self,
        commit: PreparedStreamingBodyCommit,
    ) -> Result<(), CommitStreamingBodyWriteError> {
        let PreparedStreamingBodyCommit { header, body_len } = commit;
        self.commit_message_write(header);
        *self
            .streaming_body()
            .context(commit_streaming_body_write_error::BodyModeSnafu)? += body_len;
        Ok(())
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, BodyState::Streaming { .. })
    }

    pub fn is_buffered(&self) -> bool {
        matches!(self.body, BodyState::Buffered { .. })
    }

    /// Set body to buffered mode with given content
    pub fn set_body(&mut self, content: impl IntoBody) -> Result<(), SetBodyError> {
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body => return Err(SetBodyError::BodyReplacementDuringSend),
            MessageStage::Trailer | MessageStage::Complete => {
                return Err(SetBodyError::BodyAlreadyComplete);
            }
        }

        self.body = BodyState::Buffered {
            buflist: BuflistCursor::new(content.into_body()),
        };
        Ok(())
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.trailer.header_map()
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, MutateTrailersError> {
        if self.stage > MessageStage::Trailer {
            return Err(MutateTrailersError::AlreadySent);
        }
        Ok(self.trailer.header_map_mut())
    }

    pub(crate) fn trailers_mut_unchecked(&mut self) -> &mut HeaderMap {
        self.trailer.header_map_mut()
    }

    pub fn stage(&self) -> MessageStage {
        self.stage
    }

    pub fn is_complete(&self) -> bool {
        self.stage() == MessageStage::Complete
    }

    /// Reset the message to unsent state
    pub fn to_unsend(mut self) -> Self {
        self.stage = MessageStage::Header;
        self.body.reset_buffer_cursor();
        self
    }
}

impl Message<RequestHeader> {
    pub fn method(&self) -> &Method {
        self.header.method()
    }

    pub fn uri(&self) -> Uri {
        self.header.uri()
    }
}

impl Message<ResponseHeader> {
    pub fn status(&self) -> StatusCode {
        self.header.status()
    }

    pub fn header_mut(&mut self) -> Result<&mut ResponseHeader, MutateHeaderError> {
        self.header_mut_checked()
    }

    pub(crate) fn header_mut_unchecked(&mut self) -> &mut ResponseHeader {
        &mut self.header
    }
}

impl Default for ResponseMessage {
    fn default() -> Self {
        Self::new(ResponseHeader::default())
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadToStringError {
    #[snafu(display("failed to read buffered body as string"))]
    Body { source: ReadBufferedBodyError },
    #[snafu(transparent)]
    Utf8 { source: std::string::FromUtf8Error },
}

async fn write_data_to(
    stream: &mut MessageWriter,
    data: impl Buf + Send,
) -> Result<(), MessageStreamError> {
    stream.write_data(data).await
}

impl<H> Message<H>
where
    H: BeMessageHeader + TryFrom<FieldSection, Error = MalformedHeaderSection>,
{
    async fn try_read_io<T>(
        &mut self,
        stream: &mut MessageReader,
        f: impl AsyncFnOnce(&mut MessageReader, &mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        stream
            .try_stream_read(async move |stream| f(stream, self).await)
            .await
    }

    pub async fn read_from(stream: &mut MessageReader) -> Result<Self, MessageStreamError> {
        let header = stream
            .try_stream_read(async |stream| {
                let Some(field_section) = stream.read_header_frame().await? else {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameType.into());
                    }
                    return Err(H3MessageError::MissingHeaderSection.into());
                };
                Ok(H::try_from(field_section)?)
            })
            .await?;
        let stage = if header.is_interim() {
            MessageStage::Header
        } else {
            MessageStage::Body
        };
        Ok(Self {
            header,
            body: BodyState::Pending,
            trailer: Trailer::default(),
            stage,
        })
    }

    pub async fn read_header_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Result<&H, MessageStreamError> {
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {
                return Ok(&self.header);
            }
        }

        self.header = self
            .try_read_io(stream, async |stream, _message| {
                let Some(field_section) = stream.read_header_frame().await? else {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameType.into());
                    }
                    return Err(H3MessageError::MissingHeaderSection.into());
                };
                Ok(H::try_from(field_section)?)
            })
            .await?;

        if self.is_interim_response() {
            self.stage = MessageStage::Header;
        } else {
            self.stage = MessageStage::Body;
        }
        Ok(&self.header)
    }

    pub async fn read_streaming_body_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Option<Result<Bytes, ReadStreamingBodyError>> {
        match self
            .prepare_streaming_body_read()
            .context(read_streaming_body_error::PrepareSnafu)
        {
            Ok(BodyReadAction::Ready) => {}
            Ok(BodyReadAction::Complete) => return None,
            Err(error) => return Some(Err(error)),
        }

        match self.stage {
            MessageStage::Header => {
                while self.stage == MessageStage::Header {
                    if let Err(error) = self
                        .read_header_from(stream)
                        .await
                        .context(read_streaming_body_error::StreamSnafu)
                    {
                        return Some(Err(error));
                    }
                }
                debug_assert_eq!(self.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                unreachable!("completed message body should return before reading streaming body")
            }
        }

        let try_read_next_chunk = self.try_read_io(stream, async |stream, message| {
            match stream.read_data_frame_chunk().await? {
                Some(chunk) => Ok(Some(chunk)),
                None => {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        message.stage = MessageStage::Trailer;
                    } else {
                        message.stage = MessageStage::Complete;
                    }
                    Ok(None)
                }
            }
        });

        match try_read_next_chunk
            .await
            .context(read_streaming_body_error::StreamSnafu)
        {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn read_buffered_body_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Result<impl Buf + '_, ReadBufferedBodyError> {
        match self
            .prepare_buffered_body_read()
            .context(read_buffered_body_error::PrepareSnafu)
        {
            Ok(BodyReadAction::Ready | BodyReadAction::Complete) => {}
            Err(error) => return Err(error),
        }

        match self.stage {
            MessageStage::Header => {
                while self.stage == MessageStage::Header {
                    self.read_header_from(stream)
                        .await
                        .context(read_buffered_body_error::StreamSnafu)?;
                }
            }
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {}
        }

        while self.stage == MessageStage::Body {
            let next = self
                .try_read_io(stream, async |stream, message| {
                    match stream.read_data_frame_chunk().await? {
                        Some(chunk) => Ok(Some(chunk)),
                        None => {
                            if stream.peek_frame().await.transpose()?.is_some() {
                                message.stage = MessageStage::Trailer;
                            } else {
                                message.stage = MessageStage::Complete;
                            }
                            Ok(None)
                        }
                    }
                })
                .await
                .context(read_buffered_body_error::StreamSnafu)?;

            let Some(body_part) = next else { break };
            let BodyState::Buffered { buflist } = &mut self.body else {
                unreachable!("message body mode changed while reading buffered body")
            };
            buflist.write(body_part);
        }

        let BodyState::Buffered { buflist } = &mut self.body else {
            unreachable!("message body mode changed while reading buffered body")
        };
        Ok(buflist)
    }

    pub async fn collect_bytes_body_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Result<Bytes, ReadBufferedBodyError> {
        let mut bytes = self.read_buffered_body_from(stream).await?;
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }

    pub async fn collect_string_body_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Result<String, ReadToStringError> {
        let mut body = self
            .read_buffered_body_from(stream)
            .await
            .context(read_to_string_error::BodySnafu)?;
        let mut vec = Vec::with_capacity(body.remaining());
        while body.has_remaining() {
            let chunk = body.chunk();
            vec.extend_from_slice(chunk);
            let len = chunk.len();
            body.advance(len);
        }
        Ok(String::from_utf8(vec)?)
    }

    pub async fn read_trailers_from(
        &mut self,
        stream: &mut MessageReader,
    ) -> Result<&HeaderMap, ReadTrailersError> {
        match self.stage {
            MessageStage::Header | MessageStage::Body => match &self.body {
                BodyState::Pending | BodyState::Buffered { .. } => {
                    self.read_buffered_body_from(stream)
                        .await
                        .context(read_trailers_error::BodySnafu)?;
                }
                BodyState::Streaming { .. } => {
                    return Err(ReadTrailersError::StreamingBody);
                }
            },
            MessageStage::Trailer => {}
            MessageStage::Complete => return Ok(self.trailers()),
        }

        self.trailer = self
            .try_read_io(stream, async |stream, _| {
                let Some(field_section) = stream.read_header_frame().await? else {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameDuringTrailer.into());
                    } else {
                        return Ok(Trailer::default());
                    }
                };

                Ok(Trailer::try_from(field_section)?)
            })
            .await
            .context(read_trailers_error::StreamSnafu)?;

        self.stage = MessageStage::Complete;
        Ok(self.trailers())
    }

    pub async fn read_all_from(&mut self, stream: &mut MessageReader) -> Result<(), ReadAllError> {
        self.read_header_from(stream)
            .await
            .context(read_all_error::HeaderSnafu)?;
        self.read_buffered_body_from(stream)
            .await
            .context(read_all_error::BodySnafu)?;
        self.read_trailers_from(stream)
            .await
            .context(read_all_error::TrailersSnafu)?;
        Ok(())
    }

    pub fn write_next_part_to<'m, 's>(
        &'m mut self,
        stream: &'s mut MessageWriter,
        goal: MessageWriteGoal,
    ) -> impl Future<Output = MessageWriteFlow> + use<'m, 's, H> {
        let prepared = prepare_message_write_next_part_to(self, goal);
        async move {
            match execute_prepared_message_write(stream, prepared).await {
                Ok(executed) => {
                    self.commit_message_write(executed.commit);
                    executed.flow.into_control_flow()
                }
                Err(error) => ControlFlow::Break(Err(error)),
            }
        }
    }

    pub(crate) fn prepare_message_write(&mut self, goal: MessageWriteGoal) -> PreparedMessageWrite {
        prepare_message_write_next_part_to(self, goal)
    }

    pub async fn write_header_to(
        &mut self,
        stream: &mut MessageWriter,
    ) -> Result<(), MessageStreamError> {
        drive_message_to(self, stream, MessageWriteGoal::Header).await
    }

    pub fn write_streaming_body_to<'m, 's, B>(
        &'m mut self,
        stream: &'s mut MessageWriter,
        content: B,
    ) -> impl Future<Output = Result<(), WriteStreamingBodyError>> + use<'m, 's, B, H>
    where
        B: IntoBody,
    {
        let action = match self.prepare_streaming_body_write(content) {
            Ok(prepared) => StreamingBodyAction::Send { prepared },
            Err(error) => StreamingBodyAction::Malformed(error),
        };

        async move {
            match action {
                StreamingBodyAction::Send { prepared } => {
                    let commit = execute_prepared_streaming_body_write(stream, prepared)
                        .await
                        .context(write_streaming_body_error::StreamSnafu)?;
                    self.commit_streaming_body_write(commit)
                        .context(write_streaming_body_error::CommitSnafu)
                }
                StreamingBodyAction::Malformed(error) => {
                    _ = stream.reset(Code::H3_MESSAGE_ERROR).await;
                    Err(error).context(write_streaming_body_error::PrepareSnafu)
                }
            }
        }
    }

    pub async fn write_buffered_body_to(
        &mut self,
        stream: &mut MessageWriter,
    ) -> Result<(), WriteBufferedBodyError> {
        self.buffered_body()
            .context(write_buffered_body_error::BodyModeSnafu)?;
        drive_message_to(self, stream, MessageWriteGoal::Body)
            .await
            .context(write_buffered_body_error::StreamSnafu)
    }

    pub async fn write_trailers_to(
        &mut self,
        stream: &mut MessageWriter,
    ) -> Result<(), MessageStreamError> {
        if matches!(self.stage, MessageStage::Header | MessageStage::Body)
            && matches!(self.body, BodyState::Pending)
        {
            self.body = BodyState::Buffered {
                buflist: BuflistCursor::new(BufList::new()),
            };
        }
        drive_message_to(self, stream, MessageWriteGoal::Complete).await
    }

    pub async fn write_all_to(
        &mut self,
        stream: &mut MessageWriter,
    ) -> Result<(), MessageStreamError> {
        drive_message_to(self, stream, MessageWriteGoal::Complete).await
    }
}

async fn write_trailer_header(
    stream: &mut MessageWriter,
    field_lines: impl IntoIterator<Item = FieldLine> + Send,
) -> Result<(), MessageStreamError> {
    match stream.write_header(field_lines).await {
        Ok(()) => Ok(()),
        Err(MessageStreamError::HeaderTooLarge) => Err(MessageStreamError::TrailerTooLarge),
        Err(error) => Err(error),
    }
}

async fn drive_message_to<H>(
    message: &mut Message<H>,
    stream: &mut MessageWriter,
    goal: MessageWriteGoal,
) -> Result<(), MessageStreamError>
where
    H: BeMessageHeader + TryFrom<FieldSection, Error = MalformedHeaderSection>,
{
    loop {
        match message.write_next_part_to(stream, goal).await {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(result) => {
                return result;
            }
        }
    }
}

enum MessageWriteStepAction {
    BreakOk,
    Header {
        fields: Vec<FieldLine>,
        flow: MessageWriteStepFlow,
    },
    Data {
        data: Bytes,
        flow: MessageWriteStepFlow,
    },
    Trailer(Vec<FieldLine>),
}

pub(crate) struct PreparedMessageWrite {
    action: MessageWriteStepAction,
    commit: MessageWriteCommit,
    in_flight_stage: Option<MessageStage>,
}

impl PreparedMessageWrite {
    fn break_ok(commit: MessageWriteCommit) -> Self {
        Self {
            action: MessageWriteStepAction::BreakOk,
            commit,
            in_flight_stage: None,
        }
    }

    fn write(
        action: MessageWriteStepAction,
        commit: MessageWriteCommit,
        in_flight_stage: MessageStage,
    ) -> Self {
        Self {
            action,
            commit,
            in_flight_stage: Some(in_flight_stage),
        }
    }

    pub(crate) fn in_flight_stage(&self) -> Option<MessageStage> {
        self.in_flight_stage
    }

    pub(crate) fn try_into_executed_without_io(self) -> Result<ExecutedMessageWrite, Self> {
        let Self {
            action,
            commit,
            in_flight_stage,
        } = self;
        match action {
            MessageWriteStepAction::BreakOk => Ok(ExecutedMessageWrite {
                commit,
                flow: MessageWriteStepFlow::BreakOk,
            }),
            action => Err(Self {
                action,
                commit,
                in_flight_stage,
            }),
        }
    }

    #[cfg(test)]
    fn action(&self) -> &MessageWriteStepAction {
        &self.action
    }
}

pub(crate) struct ExecutedMessageWrite {
    commit: MessageWriteCommit,
    flow: MessageWriteStepFlow,
}

#[derive(Debug, Clone, Copy)]
enum MessageWriteCommit {
    None,
    Stage(MessageStage),
    BufferedBody {
        advance: usize,
        stage_after: Option<MessageStage>,
    },
}

impl MessageWriteCommit {
    fn apply<H: BeMessageHeader>(self, message: &mut Message<H>) {
        match self {
            MessageWriteCommit::None => {}
            MessageWriteCommit::Stage(stage) => {
                message.stage = stage;
            }
            MessageWriteCommit::BufferedBody {
                advance,
                stage_after,
            } => {
                let BodyState::Buffered { buflist } = &mut message.body else {
                    unreachable!("message body mode changed before committing buffered body")
                };
                buflist.advance(advance);
                if let Some(stage) = stage_after {
                    message.stage = stage;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MessageWriteStepFlow {
    BreakOk,
    Continue,
}

impl MessageWriteStepFlow {
    fn into_control_flow(self) -> MessageWriteFlow {
        match self {
            MessageWriteStepFlow::BreakOk => ControlFlow::Break(Ok(())),
            MessageWriteStepFlow::Continue => ControlFlow::Continue(()),
        }
    }
}

pub(crate) async fn execute_prepared_message_write(
    stream: &mut MessageWriter,
    prepared: PreparedMessageWrite,
) -> Result<ExecutedMessageWrite, MessageStreamError> {
    let PreparedMessageWrite { action, commit, .. } = prepared;
    let flow = match action {
        MessageWriteStepAction::BreakOk => MessageWriteStepFlow::BreakOk,
        MessageWriteStepAction::Header { fields, flow } => {
            stream.write_header(fields).await?;
            flow
        }
        MessageWriteStepAction::Data { data, flow } => {
            write_data_to(stream, data).await?;
            flow
        }
        MessageWriteStepAction::Trailer(fields) => {
            write_trailer_header(stream, fields).await?;
            MessageWriteStepFlow::BreakOk
        }
    };
    Ok(ExecutedMessageWrite { commit, flow })
}

impl<H: BeMessageHeader> Message<H> {
    fn commit_message_write(&mut self, commit: MessageWriteCommit) {
        commit.apply(self);
    }

    pub(crate) fn commit_executed_message_write(
        &mut self,
        executed: ExecutedMessageWrite,
    ) -> MessageWriteFlow {
        self.commit_message_write(executed.commit);
        executed.flow.into_control_flow()
    }
}

fn prepare_message_write_next_part_to<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> PreparedMessageWrite {
    match message.stage {
        MessageStage::Header => prepare_message_header_step(message, goal),
        MessageStage::Body => match goal {
            MessageWriteGoal::Header => PreparedMessageWrite::break_ok(MessageWriteCommit::None),
            MessageWriteGoal::Body | MessageWriteGoal::Complete => {
                prepare_message_body_step(message, goal)
            }
        },
        MessageStage::Trailer => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => {
                PreparedMessageWrite::break_ok(MessageWriteCommit::None)
            }
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        MessageStage::Complete => PreparedMessageWrite::break_ok(MessageWriteCommit::None),
    }
}

fn prepare_message_header_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> PreparedMessageWrite {
    let fields = message.header.iter().collect::<Vec<_>>();
    let is_interim = message.is_interim_response();

    let flow = if is_interim {
        MessageWriteStepFlow::BreakOk
    } else {
        match goal {
            MessageWriteGoal::Header => MessageWriteStepFlow::BreakOk,
            MessageWriteGoal::Body => {
                if message.is_buffered() {
                    MessageWriteStepFlow::Continue
                } else {
                    MessageWriteStepFlow::BreakOk
                }
            }
            MessageWriteGoal::Complete => MessageWriteStepFlow::Continue,
        }
    };

    let commit = if is_interim {
        MessageWriteCommit::None
    } else {
        MessageWriteCommit::Stage(MessageStage::Body)
    };
    let in_flight_stage = if is_interim {
        MessageStage::Header
    } else {
        MessageStage::Body
    };

    PreparedMessageWrite::write(
        MessageWriteStepAction::Header { fields, flow },
        commit,
        in_flight_stage,
    )
}

fn prepare_message_body_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> PreparedMessageWrite {
    match &message.body {
        BodyState::Pending => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => {
                PreparedMessageWrite::break_ok(MessageWriteCommit::None)
            }
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        BodyState::Streaming { .. } => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => {
                PreparedMessageWrite::break_ok(MessageWriteCommit::None)
            }
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        BodyState::Buffered { .. } => prepare_message_buffered_body_step(message, goal),
    }
}

fn prepare_message_buffered_body_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> PreparedMessageWrite {
    let data = {
        let BodyState::Buffered { buflist } = &mut message.body else {
            unreachable!("message body mode changed while preparing buffered body")
        };

        if buflist.has_remaining() {
            let data = buflist
                .iter()
                .next()
                .expect("buffered body with remaining bytes must have a chunk");
            let advance = data.len();
            let completes_body = buflist.remaining() == advance;
            Some((data, advance, completes_body))
        } else {
            None
        }
    };

    match data {
        Some((data, advance, completes_body)) => {
            let flow = if completes_body {
                match goal {
                    MessageWriteGoal::Complete => MessageWriteStepFlow::Continue,
                    MessageWriteGoal::Header | MessageWriteGoal::Body => {
                        MessageWriteStepFlow::BreakOk
                    }
                }
            } else {
                MessageWriteStepFlow::Continue
            };
            let stage_after = completes_body.then_some(MessageStage::Trailer);
            let in_flight_stage = stage_after.unwrap_or(MessageStage::Body);
            PreparedMessageWrite::write(
                MessageWriteStepAction::Data { data, flow },
                MessageWriteCommit::BufferedBody {
                    advance,
                    stage_after,
                },
                in_flight_stage,
            )
        }
        None => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => {
                PreparedMessageWrite::break_ok(MessageWriteCommit::Stage(MessageStage::Trailer))
            }
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
    }
}

fn prepare_message_trailer_step<H: BeMessageHeader>(
    message: &mut Message<H>,
) -> PreparedMessageWrite {
    if message.trailers().is_empty() {
        PreparedMessageWrite::break_ok(MessageWriteCommit::Stage(MessageStage::Complete))
    } else {
        let fields = message.trailer.iter().collect::<Vec<_>>();
        PreparedMessageWrite::write(
            MessageWriteStepAction::Trailer(fields),
            MessageWriteCommit::Stage(MessageStage::Complete),
            MessageStage::Complete,
        )
    }
}

enum StreamingBodyAction<B> {
    Send { prepared: B },
    Malformed(PrepareStreamingBodyWriteError),
}

pub(crate) struct PreparedStreamingBody {
    header: PreparedMessageWrite,
    content: Body,
    body_len: u64,
}

impl PreparedStreamingBody {
    #[cfg(test)]
    pub(crate) fn body_len(&self) -> u64 {
        self.body_len
    }

    pub(crate) fn in_flight_stage(&self) -> Option<MessageStage> {
        Some(MessageStage::Body).max(self.header.in_flight_stage())
    }
}

pub(crate) struct PreparedStreamingBodyCommit {
    header: MessageWriteCommit,
    body_len: u64,
}

pub(crate) async fn execute_prepared_streaming_body_write(
    stream: &mut MessageWriter,
    prepared: PreparedStreamingBody,
) -> Result<PreparedStreamingBodyCommit, MessageStreamError> {
    let PreparedStreamingBody {
        header,
        content,
        body_len,
    } = prepared;
    let header = execute_prepared_message_write(stream, header).await?;
    match header.flow {
        MessageWriteStepFlow::BreakOk => {}
        MessageWriteStepFlow::Continue => {
            unreachable!("header goal cannot require another write step")
        }
    }
    write_data_to(stream, content).await?;
    Ok(PreparedStreamingBodyCommit {
        header: header.commit,
        body_len,
    })
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::rc::Rc;

    use bytes::{Buf, Bytes, BytesMut};

    use crate::h3x::dhttp::message::{MessageReader, MessageWriter};

    use super::{
        Body, BodyState, IntoAuthority, IntoAuthorityError, IntoBody, IntoUri, IntoUriError,
    };

    struct NonSendBody(Rc<Vec<u8>>);

    impl IntoBody for NonSendBody {
        fn into_body(self) -> Body {
            self.0.as_slice().into_body()
        }
    }

    fn collect_body(mut body: Body) -> Bytes {
        body.copy_to_bytes(body.remaining())
    }

    fn commit_prepared_write<H: super::BeMessageHeader>(
        message: &mut super::Message<H>,
        prepared: super::PreparedMessageWrite,
    ) {
        message.commit_message_write(prepared.commit);
    }

    #[test]
    fn into_body_accepts_common_owned_and_borrowed_types() {
        assert_eq!(collect_body("hello".into_body()), b"hello"[..]);
        assert_eq!(
            collect_body(String::from("owned string").into_body()),
            b"owned string"[..]
        );
        assert_eq!(collect_body(vec![1, 2, 3].into_body()), [1, 2, 3][..]);
        assert_eq!(
            collect_body(Bytes::from_static(b"bytes").into_body()),
            b"bytes"[..]
        );
        assert_eq!(
            collect_body(BytesMut::from(&b"bytes mut"[..]).into_body()),
            b"bytes mut"[..]
        );

        let borrowed_bytes: &[u8] = b"borrowed bytes";
        let borrowed_string = String::from("borrowed string");
        assert_eq!(
            collect_body(borrowed_bytes.into_body()),
            b"borrowed bytes"[..]
        );
        assert_eq!(
            collect_body((&borrowed_string).into_body()),
            b"borrowed string"[..]
        );
    }

    #[test]
    fn body_alias_is_the_public_payload_body() {
        let body: Body = Bytes::from_static(b"alias body").into_body();
        assert_eq!(collect_body(body), b"alias body"[..]);
    }

    #[test]
    fn preparing_streaming_body_write_does_not_increment_count() {
        let mut message = super::ResponseMessage::default();

        let prepared = message
            .prepare_streaming_body_write("hello")
            .expect("streaming body write can be prepared before transfer starts");

        assert_eq!(prepared.body_len(), 5);
        assert_eq!(*message.streaming_body().unwrap(), 0);
    }

    #[test]
    fn header_write_preparation_does_not_advance_stage() {
        let mut message = super::ResponseMessage::default();

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Header,
        );

        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Header { .. }
        ));
        assert_eq!(message.stage(), super::MessageStage::Header);
    }

    #[test]
    fn buffered_body_write_preparation_does_not_advance_stage_or_cursor() {
        let mut message = super::ResponseMessage::default();
        message.set_body("body").unwrap();
        message.stage = super::MessageStage::Body;

        let prepared =
            super::prepare_message_write_next_part_to(&mut message, super::MessageWriteGoal::Body);

        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Data { .. }
        ));
        assert_eq!(message.stage(), super::MessageStage::Body);
        let BodyState::Buffered { buflist } = &message.body else {
            panic!("body should remain buffered");
        };
        assert_eq!(buflist.remaining(), 4);
    }

    #[test]
    fn trailer_write_preparation_does_not_complete_stage() {
        let mut message = super::ResponseMessage {
            header: super::ResponseHeader::default(),
            body: BodyState::Pending,
            trailer: super::Trailer::default(),
            stage: super::MessageStage::Trailer,
        };
        message
            .trailers_mut()
            .unwrap()
            .insert("x-test", http::HeaderValue::from_static("1"));

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );

        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Trailer(_)
        ));
        assert_eq!(message.stage(), super::MessageStage::Trailer);
    }

    #[test]
    fn committing_streaming_body_write_increments_count() {
        let mut message = super::ResponseMessage::default();
        let prepared = message
            .prepare_streaming_body_write("hello")
            .expect("streaming body write can be prepared before transfer starts");

        message
            .commit_streaming_body_write(super::PreparedStreamingBodyCommit {
                header: prepared.header.commit,
                body_len: prepared.body_len(),
            })
            .expect("prepared streaming body write can be committed");

        assert_eq!(*message.streaming_body().unwrap(), 5);
    }

    #[test]
    fn streaming_read_preparation_does_not_reselect_body_after_complete() {
        let mut message = super::ResponseMessage::default();
        message.set_body("done").unwrap();
        message.stage = super::MessageStage::Complete;

        let action = message
            .prepare_streaming_body_read()
            .expect("completed body should be a valid end of stream");

        assert_eq!(action, super::BodyReadAction::Complete);
        assert!(message.is_buffered());
    }

    #[test]
    fn buffered_read_preparation_reuses_buffered_body_after_trailer_stage() {
        let mut message = super::ResponseMessage::default();
        message.set_body("done").unwrap();
        message.stage = super::MessageStage::Trailer;

        let action = message
            .prepare_buffered_body_read()
            .expect("buffered body can be reused after body is complete");

        assert_eq!(action, super::BodyReadAction::Complete);
        assert!(message.is_buffered());
    }

    #[test]
    fn streaming_body_reports_buffered_mode_error() {
        let mut message = super::ResponseMessage::default();
        message.set_body("buffered").unwrap();

        let error = message.streaming_body().unwrap_err();

        assert!(matches!(
            error,
            super::EnsureStreamingBodyError::BufferedBody
        ));
    }

    #[test]
    fn set_body_reports_replacement_during_body_stage() {
        let mut message = super::ResponseMessage::default();
        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Header,
        );
        commit_prepared_write(&mut message, prepared);

        let error = message.set_body("late body").unwrap_err();

        assert!(matches!(
            error,
            super::SetBodyError::BodyReplacementDuringSend
        ));
    }

    #[test]
    fn complete_write_preparation_accepts_streaming_body() {
        let mut message = super::ResponseMessage::default();
        *message.streaming_body().unwrap() += 5;

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert!(message.is_streaming());
        assert_eq!(message.stage(), super::MessageStage::Header);
        commit_prepared_write(&mut message, prepared);

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::BreakOk
        ));
        commit_prepared_write(&mut message, prepared);
        assert_eq!(message.stage(), super::MessageStage::Complete);
    }

    #[test]
    fn set_body_accepts_non_send_into_body() {
        let mut message = super::ResponseMessage::default();
        message
            .set_body(NonSendBody(Rc::new(b"non send body".to_vec())))
            .expect("non-Send body should be accepted");

        let BodyState::Buffered { mut buflist } = message.body else {
            panic!("body should be buffered");
        };
        assert_eq!(
            buflist.copy_to_bytes(buflist.remaining()),
            b"non send body"[..]
        );
    }

    #[allow(dead_code)]
    fn write_streaming_body_accepts_non_send_into_body(
        message: &mut super::ResponseMessage,
        stream: &mut MessageWriter,
        body: NonSendBody,
    ) {
        let _future = message.write_streaming_body_to(stream, body);
    }

    #[allow(dead_code)]
    fn read_streaming_body_returns_operation_error<'a>(
        message: &'a mut super::ResponseMessage,
        stream: &'a mut MessageReader,
    ) -> impl Future<Output = Option<Result<Bytes, super::ReadStreamingBodyError>>> + 'a {
        message.read_streaming_body_from(stream)
    }

    #[allow(dead_code)]
    fn read_buffered_body_returns_operation_error<'a>(
        message: &'a mut super::ResponseMessage,
        stream: &'a mut MessageReader,
    ) -> impl Future<Output = Result<impl Buf + 'a, super::ReadBufferedBodyError>> + 'a {
        message.read_buffered_body_from(stream)
    }

    #[allow(dead_code)]
    fn write_streaming_body_returns_operation_error<'a>(
        message: &'a mut super::ResponseMessage,
        stream: &'a mut MessageWriter,
    ) -> impl Future<Output = Result<(), super::WriteStreamingBodyError>> + 'a {
        message.write_streaming_body_to(stream, "body")
    }

    #[test]
    fn internal_message_body_state_is_not_public_payload_body() {
        let state = BodyState::Pending;
        assert!(matches!(state, BodyState::Pending));
    }

    #[test]
    fn into_uri_accepts_common_owned_and_borrowed_types() {
        let expected: http::Uri = "https://example.com/api".parse().unwrap();

        assert_eq!("https://example.com/api".into_uri(None).unwrap(), expected);
        assert_eq!(
            String::from("https://example.com/api")
                .into_uri(None)
                .unwrap(),
            expected
        );
        let owned = String::from("https://example.com/api");
        assert_eq!((&owned).into_uri(None).unwrap(), expected);
        assert_eq!(
            b"https://example.com/api"
                .as_slice()
                .into_uri(None)
                .unwrap(),
            expected
        );
        assert_eq!(
            b"https://example.com/api".to_vec().into_uri(None).unwrap(),
            expected
        );
        assert_eq!(expected.clone().into_uri(None).unwrap(), expected);
        assert_eq!((&expected).into_uri(None).unwrap(), expected);
    }

    #[test]
    fn into_uri_preserves_parse_error_type() {
        let error = "://not a uri".into_uri(None).unwrap_err();

        assert!(matches!(error, IntoUriError::Parse { .. }));
    }

    #[test]
    fn into_authority_expands_dhttp_shorthand_with_base() {
        let self_name = "self.host".parse::<crate::name::DhttpName>().unwrap();

        let authority = "alice@reimu.pilot~:443"
            .into_authority(Some(&self_name))
            .unwrap();

        assert_eq!(authority.as_str(), "alice@reimu.pilot.dhttp.net:443");
    }

    #[test]
    fn into_authority_rejects_bare_tilde_without_base() {
        let error = "~".into_authority(None).unwrap_err();

        assert!(matches!(
            error,
            IntoAuthorityError::Expand {
                source: crate::name::ExpandAuthorityError::MissingBaseName
            }
        ));
    }

    #[test]
    fn into_uri_normalizes_authority_and_reconstructs_uri() {
        let self_name = "self.host".parse::<crate::name::DhttpName>().unwrap();

        let uri = "https://alice@reimu.pilot~:443/api?q=1"
            .into_uri(Some(&self_name))
            .unwrap();

        assert_eq!(
            uri.to_string(),
            "https://alice@reimu.pilot.dhttp.net:443/api?q=1"
        );
    }

    #[test]
    fn request_header_from_field_section_accepts_https_header() {
        let section = crate::h3x::qpack::field::FieldSection::header(
            crate::h3x::qpack::field::PseudoHeaders::request(
                http::Method::GET,
                "https://example.com/api".parse().unwrap(),
            ),
            http::HeaderMap::new(),
        );

        let header = super::RequestHeader::try_from(section).unwrap();

        assert_eq!(header.method(), &http::Method::GET);
        assert_eq!(header.scheme(), &http::uri::Scheme::HTTPS);
        assert_eq!(header.authority().as_str(), "example.com");
        assert_eq!(header.path().as_str(), "/api");
        assert_eq!(
            header.uri(),
            "https://example.com/api".parse::<http::Uri>().unwrap()
        );
    }

    #[test]
    fn request_header_from_field_section_rejects_response_header() {
        let section = crate::h3x::qpack::field::FieldSection::header(
            crate::h3x::qpack::field::PseudoHeaders::response(http::StatusCode::OK),
            http::HeaderMap::new(),
        );

        let error = super::RequestHeader::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            crate::h3x::qpack::field::MalformedHeaderSection::ResponsePseudoHeaderInRequest
        ));
    }

    #[test]
    fn request_header_from_field_section_rejects_authority_only_connect_shape() {
        let section = crate::h3x::qpack::field::FieldSection::header(
            crate::h3x::qpack::field::PseudoHeaders::Request {
                method: Some(http::Method::CONNECT),
                scheme: None,
                authority: Some("example.com:443".parse().unwrap()),
                path: None,
                protocol: None,
            },
            http::HeaderMap::new(),
        );

        let error = super::RequestHeader::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            crate::h3x::qpack::field::MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. }
        ));
    }

    #[test]
    fn response_header_default_is_ok() {
        let header = super::ResponseHeader::default();

        assert_eq!(header.status(), http::StatusCode::OK);
        assert!(header.header_map().is_empty());
    }

    #[test]
    fn response_header_from_field_section_rejects_request_header() {
        let section = crate::h3x::qpack::field::FieldSection::header(
            crate::h3x::qpack::field::PseudoHeaders::request(
                http::Method::GET,
                "https://example.com/".parse().unwrap(),
            ),
            http::HeaderMap::new(),
        );

        let error = super::ResponseHeader::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            crate::h3x::qpack::field::MalformedHeaderSection::RequestPseudoHeaderInResponse
        ));
    }

    #[test]
    fn trailer_from_field_section_rejects_pseudo_headers() {
        let section = crate::h3x::qpack::field::FieldSection::header(
            crate::h3x::qpack::field::PseudoHeaders::response(http::StatusCode::OK),
            http::HeaderMap::new(),
        );

        let error = super::Trailer::try_from(section).unwrap_err();

        assert!(matches!(
            error,
            crate::h3x::qpack::field::MalformedHeaderSection::PseudoHeaderInTrailer
        ));
    }

    #[test]
    fn request_message_exposes_typed_request_header() {
        let header =
            super::RequestHeader::try_from(crate::h3x::qpack::field::FieldSection::header(
                crate::h3x::qpack::field::PseudoHeaders::request(
                    http::Method::POST,
                    "https://example.com/submit".parse().unwrap(),
                ),
                http::HeaderMap::new(),
            ))
            .unwrap();

        let message = super::RequestMessage::new(header);

        assert_eq!(message.method(), &http::Method::POST);
        assert_eq!(
            message.uri(),
            "https://example.com/submit".parse::<http::Uri>().unwrap()
        );
    }

    #[test]
    fn response_message_default_uses_ok_status() {
        let message = super::ResponseMessage::default();

        assert_eq!(message.status(), http::StatusCode::OK);
        assert_eq!(message.stage(), super::MessageStage::Header);
    }

    #[test]
    fn complete_goal_marks_empty_message_complete_after_header_sent() {
        let mut message = super::ResponseMessage::default();

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert_eq!(message.stage(), super::MessageStage::Header);
        commit_prepared_write(&mut message, prepared);
        assert_eq!(message.stage(), super::MessageStage::Body);

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );

        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::BreakOk
        ));
        commit_prepared_write(&mut message, prepared);
        assert_eq!(message.stage(), super::MessageStage::Complete);
    }

    #[test]
    fn complete_goal_marks_empty_trailer_complete_after_buffered_body() {
        let mut message = super::ResponseMessage::default();
        message.set_body("body").unwrap();

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        commit_prepared_write(&mut message, prepared);

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::Data {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert_eq!(message.stage(), super::MessageStage::Body);
        let BodyState::Buffered { buflist } = &message.body else {
            panic!("body should remain buffered");
        };
        assert_eq!(buflist.remaining(), 4);
        commit_prepared_write(&mut message, prepared);
        assert_eq!(message.stage(), super::MessageStage::Trailer);

        let prepared = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );

        assert!(matches!(
            prepared.action(),
            super::MessageWriteStepAction::BreakOk
        ));
        commit_prepared_write(&mut message, prepared);
        assert_eq!(message.stage(), super::MessageStage::Complete);
    }
}
