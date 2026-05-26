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
    error::{Code, H3FrameUnexpected, H3MessageError},
    message::stream::{MessageStreamError, ReadStream, WriteStream},
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

#[derive(Debug, Snafu)]
pub enum MalformedMessageError {
    // === 状态相关错误 ===
    #[snafu(display("cannot modify header section after it has been sent"))]
    HeaderAlreadySent,
    #[snafu(display("cannot modify body while it is being sent"))]
    BodyAlreadySending,
    #[snafu(display("cannot replace body content while sending"))]
    BodyReplacementDuringSend,
    #[snafu(display("cannot modify trailer section after it has been sent"))]
    TrailerAlreadySent,
    #[snafu(display("cannot change body mode after transfer has started"))]
    BodyModeChangeAfterTransferStarted,
    #[snafu(display("cannot modify body after transfer has ended"))]
    BodyAlreadyComplete,

    // === 模式不匹配错误 ===
    #[snafu(display("buffered body operation cannot be performed on streaming body"))]
    BufferedOperationOnStreamingBody,
    #[snafu(display("streaming body operation cannot be performed on buffered body"))]
    StreamingOperationOnBufferedBody,

    // === 协议语义错误 ===
    #[snafu(display("cannot send malformed pseudo header section"))]
    MalformedPseudoHeader { source: MalformedHeaderSection },
    #[snafu(display("cannot set body or trailer for interim (1xx) response"))]
    BodyOrTrailerOnInterimResponse,
    #[snafu(display("cannot close response stream without sending a final response"))]
    FinalResponseRequired,
}

impl From<MalformedHeaderSection> for MalformedMessageError {
    fn from(source: MalformedHeaderSection) -> Self {
        MalformedMessageError::MalformedPseudoHeader { source }
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

    fn header_mut_checked(&mut self) -> Result<&mut H, MalformedMessageError> {
        if self.stage > MessageStage::Header {
            return Err(MalformedMessageError::HeaderAlreadySent);
        }
        Ok(&mut self.header)
    }

    pub fn is_interim_response(&self) -> bool {
        self.header.is_interim()
    }

    pub fn streaming_body(&mut self) -> Result<&mut u64, MalformedMessageError> {
        if self.stage > MessageStage::Body {
            return Err(MalformedMessageError::BodyAlreadyComplete);
        }

        match &self.body {
            BodyState::Pending => self.body = BodyState::Streaming { count: 0 },
            BodyState::Streaming { .. } => {}
            BodyState::Buffered { .. } => {
                return Err(MalformedMessageError::StreamingOperationOnBufferedBody);
            }
        }
        match &mut self.body {
            BodyState::Pending => unreachable!(),
            BodyState::Streaming { count } => Ok(count),
            BodyState::Buffered { .. } => unreachable!(),
        }
    }

    pub fn buffered_body(&mut self) -> Result<&mut BuflistCursor, MalformedMessageError> {
        if self.stage > MessageStage::Body {
            return Err(MalformedMessageError::BodyAlreadyComplete);
        }

        match &self.body {
            BodyState::Pending => {
                self.body = BodyState::Buffered {
                    buflist: BuflistCursor::new(BufList::new()),
                };
            }
            BodyState::Buffered { .. } => {}
            BodyState::Streaming { .. } => {
                return Err(MalformedMessageError::BufferedOperationOnStreamingBody);
            }
        }
        match &mut self.body {
            BodyState::Pending => unreachable!(),
            BodyState::Streaming { .. } => unreachable!(),
            BodyState::Buffered { buflist } => Ok(buflist),
        }
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, BodyState::Streaming { .. })
    }

    pub fn is_buffered(&self) -> bool {
        matches!(self.body, BodyState::Buffered { .. })
    }

    /// Set body to buffered mode with given content
    pub fn set_body(&mut self, content: impl IntoBody) -> Result<(), MalformedMessageError> {
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body => return Err(MalformedMessageError::BodyReplacementDuringSend),
            MessageStage::Trailer | MessageStage::Complete => {
                return Err(MalformedMessageError::BodyAlreadyComplete);
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

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, MalformedMessageError> {
        if self.stage > MessageStage::Trailer {
            return Err(MalformedMessageError::TrailerAlreadySent);
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

    pub fn header_mut(&mut self) -> Result<&mut ResponseHeader, MalformedMessageError> {
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
pub enum ReadToStringError {
    #[snafu(transparent)]
    Stream { source: MessageStreamError },
    #[snafu(transparent)]
    Utf8 { source: std::string::FromUtf8Error },
}

async fn send_data_to(
    stream: &mut WriteStream,
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
        stream: &mut ReadStream,
        f: impl AsyncFnOnce(&mut ReadStream, &mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        stream
            .try_stream_io(async move |stream| f(stream, self).await)
            .await
    }

    pub async fn read_from(stream: &mut ReadStream) -> Result<Self, MessageStreamError> {
        let header = stream
            .try_stream_io(async |stream| {
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
        stream: &mut ReadStream,
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
        stream: &mut ReadStream,
    ) -> Option<Result<Bytes, MessageStreamError>> {
        if let Err(_error) = self.streaming_body() {
            return Some(Err(MessageStreamError::MalformedIncomingMessage));
        }

        match self.stage {
            MessageStage::Header => {
                while self.stage == MessageStage::Header {
                    if let Err(error) = self.read_header_from(stream).await {
                        return Some(Err(error));
                    }
                }
                debug_assert_eq!(self.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => return None,
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

        match try_read_next_chunk.await {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn read_buffered_body_from(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<impl Buf + '_, MessageStreamError> {
        if let Err(_error) = self.buffered_body() {
            return Err(MessageStreamError::MalformedIncomingMessage);
        }

        match self.stage {
            MessageStage::Header => {
                while self.stage == MessageStage::Header {
                    self.read_header_from(stream).await?;
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
                .await?;

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
        stream: &mut ReadStream,
    ) -> Result<Bytes, MessageStreamError> {
        let mut bytes = self.read_buffered_body_from(stream).await?;
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }

    pub async fn collect_string_body_from(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<String, ReadToStringError> {
        let mut body = self.read_buffered_body_from(stream).await?;
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
        stream: &mut ReadStream,
    ) -> Result<&HeaderMap, MessageStreamError> {
        match self.stage {
            MessageStage::Header | MessageStage::Body => match &self.body {
                BodyState::Pending | BodyState::Buffered { .. } => {
                    self.read_buffered_body_from(stream).await?;
                }
                BodyState::Streaming { .. } => {
                    return Err(MessageStreamError::MalformedIncomingMessage);
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
            .await?;

        self.stage = MessageStage::Complete;
        Ok(self.trailers())
    }

    pub async fn read_all_from(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<(), MessageStreamError> {
        self.read_header_from(stream).await?;
        self.read_buffered_body_from(stream).await?;
        self.read_trailers_from(stream).await?;
        Ok(())
    }

    pub fn write_next_part_to<'s>(
        &mut self,
        stream: &'s mut WriteStream,
        goal: MessageWriteGoal,
    ) -> impl Future<Output = MessageWriteFlow> + use<'s, H> {
        let action = prepare_message_write_next_part_to(self, goal);
        async move { execute_message_write_next_part_to(stream, action).await }
    }

    pub async fn write_header_to(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        drive_message_to(self, stream, MessageWriteGoal::Header).await
    }

    pub fn write_streaming_body_to<'s, B>(
        &mut self,
        stream: &'s mut WriteStream,
        content: B,
    ) -> impl Future<Output = Result<(), MessageStreamError>> + use<'s, B, H>
    where
        B: IntoBody,
    {
        let content = content.into_body();
        let additional = content.remaining() as u64;
        let action = match self.stage {
            MessageStage::Header | MessageStage::Body => {
                if let Err(_error) = self.streaming_body().map(|count| *count += additional) {
                    StreamingBodyAction::Malformed
                } else {
                    StreamingBodyAction::Send {
                        header: prepare_message_write_next_part_to(self, MessageWriteGoal::Header),
                        content,
                    }
                }
            }
            MessageStage::Trailer | MessageStage::Complete => StreamingBodyAction::Malformed,
        };

        async move {
            match action {
                StreamingBodyAction::Send { header, content } => {
                    match execute_message_write_next_part_to(stream, header).await {
                        ControlFlow::Break(Ok(())) => {}
                        ControlFlow::Break(Err(error)) => return Err(error),
                        ControlFlow::Continue(()) => {
                            unreachable!("header goal cannot require another write step")
                        }
                    }
                    send_data_to(stream, content).await
                }
                StreamingBodyAction::Malformed => {
                    _ = stream.cancel(Code::H3_MESSAGE_ERROR).await;
                    Err(MessageStreamError::MessageSendFailed)
                }
            }
        }
    }

    pub async fn write_buffered_body_to(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        if let Err(_error) = self.buffered_body() {
            return Err(MessageStreamError::MessageSendFailed);
        }
        drive_message_to(self, stream, MessageWriteGoal::Body).await
    }

    pub async fn write_trailers_to(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        if matches!(self.body, BodyState::Pending) {
            self.body = BodyState::Buffered {
                buflist: BuflistCursor::new(BufList::new()),
            };
        }
        drive_message_to(self, stream, MessageWriteGoal::Complete).await
    }

    pub async fn write_all_to(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        drive_message_to(self, stream, MessageWriteGoal::Complete).await
    }
}

async fn send_trailer_header(
    stream: &mut WriteStream,
    field_lines: impl IntoIterator<Item = FieldLine> + Send,
) -> Result<(), MessageStreamError> {
    match stream.send_header(field_lines).await {
        Ok(()) => Ok(()),
        Err(MessageStreamError::HeaderTooLarge) => Err(MessageStreamError::TrailerTooLarge),
        Err(error) => Err(error),
    }
}

async fn execute_message_write_next_part_to(
    stream: &mut WriteStream,
    action: MessageWriteStepAction,
) -> MessageWriteFlow {
    match action {
        MessageWriteStepAction::BreakOk => ControlFlow::Break(Ok(())),
        MessageWriteStepAction::Header { fields, flow } => match stream.send_header(fields).await {
            Ok(()) => flow.into_control_flow(),
            Err(error) => ControlFlow::Break(Err(error)),
        },
        MessageWriteStepAction::Data { data, flow } => match send_data_to(stream, data).await {
            Ok(()) => flow.into_control_flow(),
            Err(error) => ControlFlow::Break(Err(error)),
        },
        MessageWriteStepAction::Trailer(fields) => {
            match send_trailer_header(stream, fields).await {
                Ok(()) => ControlFlow::Break(Ok(())),
                Err(error) => ControlFlow::Break(Err(error)),
            }
        }
    }
}

async fn drive_message_to<H>(
    message: &mut Message<H>,
    stream: &mut WriteStream,
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

fn prepare_message_write_next_part_to<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    match message.stage {
        MessageStage::Header => prepare_message_header_step(message, goal),
        MessageStage::Body => match goal {
            MessageWriteGoal::Header => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Body | MessageWriteGoal::Complete => {
                prepare_message_body_step(message, goal)
            }
        },
        MessageStage::Trailer => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        MessageStage::Complete => MessageWriteStepAction::BreakOk,
    }
}

fn prepare_message_header_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    let fields = message.header.iter().collect::<Vec<_>>();
    let is_interim = message.is_interim_response();
    if !is_interim {
        message.stage = MessageStage::Body;
    }

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

    MessageWriteStepAction::Header { fields, flow }
}

fn prepare_message_body_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    match &message.body {
        BodyState::Pending => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        BodyState::Streaming { .. } => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        BodyState::Buffered { .. } => prepare_message_buffered_body_step(message, goal),
    }
}

fn prepare_message_buffered_body_step<H: BeMessageHeader>(
    message: &mut Message<H>,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    let data = {
        let BodyState::Buffered { buflist } = &mut message.body else {
            unreachable!("message body mode changed while preparing buffered body")
        };

        if buflist.has_remaining() {
            let data = buflist.copy_to_bytes(buflist.chunk().len());
            if !buflist.has_remaining() {
                message.stage = MessageStage::Trailer;
            }
            Some(data)
        } else {
            message.stage = MessageStage::Trailer;
            None
        }
    };

    match data {
        Some(data) => {
            let flow = if message.stage == MessageStage::Trailer {
                match goal {
                    MessageWriteGoal::Complete => MessageWriteStepFlow::Continue,
                    MessageWriteGoal::Header | MessageWriteGoal::Body => {
                        MessageWriteStepFlow::BreakOk
                    }
                }
            } else {
                MessageWriteStepFlow::Continue
            };
            MessageWriteStepAction::Data { data, flow }
        }
        None => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
    }
}

fn prepare_message_trailer_step<H: BeMessageHeader>(
    message: &mut Message<H>,
) -> MessageWriteStepAction {
    message.stage = MessageStage::Complete;
    if message.trailers().is_empty() {
        MessageWriteStepAction::BreakOk
    } else {
        let fields = message.trailer.iter().collect::<Vec<_>>();
        MessageWriteStepAction::Trailer(fields)
    }
}

enum StreamingBodyAction<B> {
    Send {
        header: MessageWriteStepAction,
        content: B,
    },
    Malformed,
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use bytes::{Buf, Bytes, BytesMut};

    use crate::h3x::message::stream::WriteStream;

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
    fn complete_write_preparation_accepts_streaming_body() {
        let mut message = super::ResponseMessage::default();
        *message.streaming_body().unwrap() += 5;

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            action,
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert!(message.is_streaming());

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(action, super::MessageWriteStepAction::BreakOk));
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
        stream: &mut WriteStream,
        body: NonSendBody,
    ) {
        let _future = message.write_streaming_body_to(stream, body);
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

        assert_eq!(authority.as_str(), "alice@reimu.pilot.genmeta.net:443");
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
            "https://alice@reimu.pilot.genmeta.net:443/api?q=1"
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

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            action,
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert_eq!(message.stage(), super::MessageStage::Body);

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );

        assert!(matches!(action, super::MessageWriteStepAction::BreakOk));
        assert_eq!(message.stage(), super::MessageStage::Complete);
    }

    #[test]
    fn complete_goal_marks_empty_trailer_complete_after_buffered_body() {
        let mut message = super::ResponseMessage::default();
        message.set_body("body").unwrap();

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            action,
            super::MessageWriteStepAction::Header {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );
        assert!(matches!(
            action,
            super::MessageWriteStepAction::Data {
                flow: super::MessageWriteStepFlow::Continue,
                ..
            }
        ));
        assert_eq!(message.stage(), super::MessageStage::Trailer);

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Complete,
        );

        assert!(matches!(action, super::MessageWriteStepAction::BreakOk));
        assert_eq!(message.stage(), super::MessageStage::Complete);
    }
}
