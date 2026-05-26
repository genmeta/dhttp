use std::{borrow::Cow, mem, ops::ControlFlow};

use bytes::{Buf, Bytes, BytesMut};
use http::{
    HeaderMap, Uri,
    header::{InvalidHeaderName, InvalidHeaderValue},
    uri::Authority,
};
use snafu::{ResultExt, Snafu};

use crate::h3x::{
    buflist::{BufList, BuflistCursor},
    connection,
    error::{Code, H3FrameUnexpected, H3MessageError},
    message::stream::{MessageStreamError, ReadStream, WriteStream},
    qpack::field::{
        FieldLine, FieldSection, MalformedHeaderSection, PseudoHeaders, malformed_header_section,
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

/// Message body transfer state.
#[derive(Debug, Clone)]
pub enum BodyState {
    Pending,
    Streaming { count: u64 },
    Buffered { buflist: BuflistCursor },
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

    /// Message struct is malformed
    Malformed = 4,
    /// Message sending failed and cannot be resumed
    Failed = 5,
    /// Message struct is already taken/dropped
    // State can be removed after async drop stabilizes
    Dropped = 6,
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
    #[snafu(display("cannot mutate malformed message"))]
    MessageMalformed,
    #[snafu(display("cannot mutate message after sending failed"))]
    MessageFailed,
    #[snafu(display("cannot mutate dropped message"))]
    MessageDropped,

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

// todo: 通过泛型区分请求和响应，避免运行时检查。虽现版本无法支持自定义泛型作为常量泛型，但可以通过零大小类型（ZST）和特化实现来达到类似效果。
#[derive(Debug, Clone)]
pub struct Message {
    header: FieldSection,
    body: BodyState,
    trailer: FieldSection,

    stage: MessageStage,
}

#[derive(Debug, Snafu)]
pub enum InvalidHeader {
    #[snafu(transparent)]
    Name { source: InvalidHeaderName },
    #[snafu(transparent)]
    Value { source: InvalidHeaderValue },
}

impl Message {
    pub fn unresolved_request() -> Self {
        Self {
            header: FieldSection::header(PseudoHeaders::unresolved_request(), HeaderMap::default()),
            body: BodyState::Pending,
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: MessageStage::Header,
        }
    }

    pub fn unresolved_response() -> Self {
        Self {
            header: FieldSection::header(
                PseudoHeaders::unresolved_response(),
                HeaderMap::default(),
            ),
            body: BodyState::Pending,
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: MessageStage::Header,
        }
    }

    pub fn is_request(&self) -> bool {
        self.header.is_request_header()
    }

    pub fn is_response(&self) -> bool {
        self.header.is_response_header()
    }

    fn terminal_stage_error(&self) -> Option<MalformedMessageError> {
        match self.stage {
            MessageStage::Malformed => Some(MalformedMessageError::MessageMalformed),
            MessageStage::Failed => Some(MalformedMessageError::MessageFailed),
            MessageStage::Dropped => Some(MalformedMessageError::MessageDropped),
            MessageStage::Header
            | MessageStage::Body
            | MessageStage::Trailer
            | MessageStage::Complete => None,
        }
    }

    pub fn streaming_body(&mut self) -> Result<&mut u64, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
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
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
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

    pub fn is_interim_response(&self) -> bool {
        self.is_response()
            && self.header().check_pseudo().is_ok()
            && self.header().status().is_informational()
    }

    pub fn header_mut(&mut self) -> Result<&mut FieldSection, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        if self.stage > MessageStage::Header {
            return Err(MalformedMessageError::HeaderAlreadySent);
        }
        Ok(&mut self.header)
    }

    pub(crate) fn header_mut_unchecked(&mut self) -> &mut FieldSection {
        &mut self.header
    }

    pub fn header(&self) -> &FieldSection {
        &self.header
    }

    pub(crate) fn validate_header_for_send(&self) -> Result<(), MalformedMessageError> {
        self.header
            .check_pseudo()
            .context(MalformedPseudoHeaderSnafu)
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, BodyState::Streaming { .. })
    }

    pub fn is_buffered(&self) -> bool {
        matches!(self.body, BodyState::Buffered { .. })
    }

    /// Set body to buffered mode with given content
    pub fn set_body(&mut self, content: impl IntoBody) -> Result<(), MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body => return Err(MalformedMessageError::BodyReplacementDuringSend),
            MessageStage::Trailer | MessageStage::Complete => {
                return Err(MalformedMessageError::BodyAlreadyComplete);
            }
            MessageStage::Malformed | MessageStage::Failed | MessageStage::Dropped => {
                unreachable!("terminal stages are checked above")
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
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
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

    pub fn is_dropped(&self) -> bool {
        self.stage() == MessageStage::Dropped
    }

    pub fn is_malformed(&self) -> bool {
        self.stage() == MessageStage::Malformed
    }

    pub fn set_malformed(&mut self) {
        self.stage = MessageStage::Malformed;
    }

    pub fn is_failed(&self) -> bool {
        self.stage() == MessageStage::Failed
    }

    pub fn set_failed(&mut self) {
        self.stage = MessageStage::Failed;
    }

    fn set_failed_unless_malformed(&mut self) {
        if !self.is_malformed() {
            self.set_failed();
        }
    }

    pub fn set_dropped(&mut self) {
        self.stage = MessageStage::Dropped;
    }

    /// Reset the message to unsent state
    pub fn to_unsend(mut self) -> Self {
        assert!(!self.is_dropped(), "cannot unsend a dropped message");
        self.stage = MessageStage::Header;
        // reset cursor
        if let BodyState::Buffered { buflist } = &mut self.body {
            buflist.reset();
        }
        self
    }

    pub fn take(&mut self) -> Self {
        assert!(!self.is_dropped(), "cannot take a dropped message");
        let message = if self.is_request() {
            mem::replace(self, Self::unresolved_request())
        } else {
            mem::replace(self, Self::unresolved_response())
        };
        self.stage = MessageStage::Dropped;

        message
    }
}

#[derive(Debug, Snafu)]
pub enum ReadToStringError {
    #[snafu(transparent)]
    Stream { source: MessageStreamError },
    #[snafu(transparent)]
    Utf8 { source: std::string::FromUtf8Error },
}

fn message_used_after_dropped() -> ! {
    unreachable!("Message used after destroyed, this is a bug");
}

async fn send_data_to(
    stream: &mut WriteStream,
    data: impl Buf + Send,
) -> Result<(), MessageStreamError> {
    stream.write_data(data).await
}

impl Message {
    async fn try_read_io<T>(
        &mut self,
        stream: &mut ReadStream,
        f: impl AsyncFnOnce(&mut ReadStream, &mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        stream
            .try_stream_io(async move |stream| {
                let result = f(stream, self).await;
                if let Err(connection::StreamError::H3 { .. }) = &result {
                    self.set_malformed();
                }
                result
            })
            .await
    }

    pub async fn read_header_from(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<&FieldSection, MessageStreamError> {
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {
                return Ok(&self.header);
            }
            MessageStage::Malformed => return Err(MessageStreamError::MalformedIncomingMessage),
            MessageStage::Failed => return Err(MessageStreamError::MessageSendFailed),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        self.header = self
            .try_read_io(stream, async |stream, message| {
                let Some(field_section) = stream.read_header_frame().await? else {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameType.into());
                    } else {
                        return Err(H3MessageError::MissingHeaderSection.into());
                    }
                };

                field_section.check_pseudo()?;
                if message.header.is_request_header() {
                    if !field_section.is_request_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                } else {
                    debug_assert!(message.header.is_response_header());
                    if !field_section.is_response_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                }
                Ok(field_section)
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
            self.set_malformed();
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
            MessageStage::Malformed => {
                return Some(Err(MessageStreamError::MalformedIncomingMessage));
            }
            MessageStage::Failed => return Some(Err(MessageStreamError::MessageSendFailed)),
            MessageStage::Dropped => message_used_after_dropped(),
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
            self.set_malformed();
            return Err(MessageStreamError::MalformedIncomingMessage);
        }

        match self.stage {
            MessageStage::Header => {
                while self.stage == MessageStage::Header {
                    self.read_header_from(stream).await?;
                }
            }
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {}
            MessageStage::Malformed => return Err(MessageStreamError::MalformedIncomingMessage),
            MessageStage::Failed => return Err(MessageStreamError::MessageSendFailed),
            MessageStage::Dropped => message_used_after_dropped(),
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
            MessageStage::Malformed => return Err(MessageStreamError::MalformedIncomingMessage),
            MessageStage::Failed => return Err(MessageStreamError::MessageSendFailed),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        self.trailer = self
            .try_read_io(stream, async |stream, _| {
                let Some(field_section) = stream.read_header_frame().await? else {
                    if stream.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameDuringTrailer.into());
                    } else {
                        return Ok(FieldSection::trailer(HeaderMap::new()));
                    }
                };

                if !field_section.is_trailer() {
                    return Err(MalformedHeaderSection::PseudoHeaderInTrailer.into());
                }
                Ok(field_section)
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
    ) -> impl Future<Output = MessageWriteFlow> + use<'s> {
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
    ) -> impl Future<Output = Result<(), MessageStreamError>> + use<'s, B>
    where
        B: IntoBody,
    {
        let content = content.into_body();
        let additional = content.remaining() as u64;
        let action = match self.stage {
            MessageStage::Header | MessageStage::Body => {
                if let Err(_error) = self.streaming_body().map(|count| *count += additional) {
                    self.set_malformed();
                    StreamingBodyAction::Cancel
                } else {
                    StreamingBodyAction::Send {
                        header: prepare_message_write_next_part_to(self, MessageWriteGoal::Header),
                        content,
                    }
                }
            }
            MessageStage::Trailer | MessageStage::Complete => {
                self.set_malformed();
                StreamingBodyAction::Cancel
            }
            MessageStage::Malformed => StreamingBodyAction::Cancel,
            MessageStage::Failed => StreamingBodyAction::Failed,
            MessageStage::Dropped => message_used_after_dropped(),
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
                StreamingBodyAction::Cancel => stream.cancel(Code::H3_REQUEST_CANCELLED).await,
                StreamingBodyAction::Failed => Err(MessageStreamError::MessageSendFailed),
            }
        }
    }

    pub async fn write_buffered_body_to(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        if let Err(_error) = self.buffered_body() {
            self.set_malformed();
            return Err(MessageStreamError::MalformedIncomingMessage);
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
        if matches!(self.stage, MessageStage::Header | MessageStage::Body)
            && self.header().is_empty()
        {
            return Ok(());
        }
        if let Err(_error) = self.buffered_body() {
            self.set_malformed();
            return Err(MessageStreamError::MalformedIncomingMessage);
        }
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
        MessageWriteStepAction::Cancel => {
            ControlFlow::Break(stream.cancel(Code::H3_REQUEST_CANCELLED).await)
        }
        MessageWriteStepAction::Malformed => {
            _ = stream.cancel(Code::H3_MESSAGE_ERROR).await;
            ControlFlow::Break(Err(MessageStreamError::MessageSendFailed))
        }
        MessageWriteStepAction::Failed => {
            ControlFlow::Break(Err(MessageStreamError::MessageSendFailed))
        }
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

async fn drive_message_to(
    message: &mut Message,
    stream: &mut WriteStream,
    goal: MessageWriteGoal,
) -> Result<(), MessageStreamError> {
    loop {
        match message.write_next_part_to(stream, goal).await {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(result) => {
                if result.is_err() {
                    message.set_failed_unless_malformed();
                }
                return result;
            }
        }
    }
}

enum MessageWriteStepAction {
    BreakOk,
    Cancel,
    Malformed,
    Failed,
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

fn prepare_message_write_next_part_to(
    message: &mut Message,
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
        MessageStage::Malformed => MessageWriteStepAction::Cancel,
        MessageStage::Failed => MessageWriteStepAction::Failed,
        MessageStage::Dropped => message_used_after_dropped(),
    }
}

fn prepare_message_header_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    if message.validate_header_for_send().is_err() {
        message.set_malformed();
        return MessageWriteStepAction::Malformed;
    }

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
            MessageWriteGoal::Complete => {
                if message.is_buffered() || !message.trailers().is_empty() {
                    MessageWriteStepFlow::Continue
                } else {
                    MessageWriteStepFlow::BreakOk
                }
            }
        }
    };

    MessageWriteStepAction::Header { fields, flow }
}

fn prepare_message_body_step(
    message: &mut Message,
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

fn prepare_message_buffered_body_step(
    message: &mut Message,
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
                    MessageWriteGoal::Complete if !message.trailers().is_empty() => {
                        MessageWriteStepFlow::Continue
                    }
                    MessageWriteGoal::Header
                    | MessageWriteGoal::Body
                    | MessageWriteGoal::Complete => MessageWriteStepFlow::BreakOk,
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

fn prepare_message_trailer_step(message: &mut Message) -> MessageWriteStepAction {
    if message.trailers().is_empty() {
        MessageWriteStepAction::BreakOk
    } else {
        let fields = message.trailer.iter().collect::<Vec<_>>();
        message.stage = MessageStage::Complete;
        MessageWriteStepAction::Trailer(fields)
    }
}

enum StreamingBodyAction<B> {
    Send {
        header: MessageWriteStepAction,
        content: B,
    },
    Cancel,
    Failed,
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use bytes::{Buf, Bytes, BytesMut};

    use crate::h3x::message::stream::WriteStream;

    use super::{
        Body, BodyState, IntoAuthority, IntoAuthorityError, IntoBody, IntoUri, IntoUriError,
        MalformedMessageError,
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
    fn request_header_validation_rejects_authority_only_get() {
        let mut message = super::Message::unresolved_request();
        message.header_mut().unwrap().set_method(http::Method::GET);
        message
            .header_mut()
            .unwrap()
            .set_authority("reimu.pilot.genmeta.net".parse().unwrap());

        let error = message.validate_header_for_send().unwrap_err();

        assert!(matches!(
            error,
            MalformedMessageError::MalformedPseudoHeader { .. }
        ));
    }

    #[test]
    fn request_header_write_step_rejects_authority_only_get() {
        let mut message = super::Message::unresolved_request();
        message.header_mut().unwrap().set_method(http::Method::GET);
        message
            .header_mut()
            .unwrap()
            .set_authority("reimu.pilot.genmeta.net".parse().unwrap());

        let action = super::prepare_message_write_next_part_to(
            &mut message,
            super::MessageWriteGoal::Header,
        );

        assert!(matches!(action, super::MessageWriteStepAction::Malformed));
        assert!(message.is_malformed());
    }

    #[test]
    fn set_body_accepts_non_send_into_body() {
        let mut message = super::Message::unresolved_request();
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
        message: &mut super::Message,
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
}
