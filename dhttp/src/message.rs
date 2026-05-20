use std::{mem, ops::ControlFlow};

use bytes::{Buf, Bytes};
use http::{
    HeaderMap,
    header::{InvalidHeaderName, InvalidHeaderValue},
};
use snafu::Snafu;

use crate::h3x::{
    buflist::{BufList, BuflistCursor},
    connection,
    dhttp::frame::Frame,
    error::{Code, H3FrameUnexpected, H3MessageError},
    message::stream::{MessageStreamError, ReadStream, WriteStream},
    qpack::field::{
        FieldLine, FieldSection, MalformedHeaderSection, PseudoHeaders, malformed_header_section,
    },
};

#[derive(Debug, Clone)]
pub enum Body {
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
    body: Body,
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
            body: Body::Pending,
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
            body: Body::Pending,
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
            Body::Pending => self.body = Body::Streaming { count: 0 },
            Body::Streaming { .. } => {}
            Body::Buffered { .. } => {
                return Err(MalformedMessageError::StreamingOperationOnBufferedBody);
            }
        }
        match &mut self.body {
            Body::Pending => unreachable!(),
            Body::Streaming { count } => Ok(count),
            Body::Buffered { .. } => unreachable!(),
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
            Body::Pending => {
                self.body = Body::Buffered {
                    buflist: BuflistCursor::new(BufList::new()),
                };
            }
            Body::Buffered { .. } => {}
            Body::Streaming { .. } => {
                return Err(MalformedMessageError::BufferedOperationOnStreamingBody);
            }
        }
        match &mut self.body {
            Body::Pending => unreachable!(),
            Body::Streaming { .. } => unreachable!(),
            Body::Buffered { buflist } => Ok(buflist),
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

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, Body::Streaming { .. })
    }

    pub fn is_buffered(&self) -> bool {
        matches!(self.body, Body::Buffered { .. })
    }

    /// Set body to buffered mode with given content
    pub fn set_body(&mut self, mut content: impl Buf) -> Result<(), MalformedMessageError> {
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

        let mut buflist = BufList::new();
        while content.has_remaining() {
            buflist.write(content.copy_to_bytes(content.chunk().len()));
        }
        self.body = Body::Buffered {
            buflist: BuflistCursor::new(buflist),
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
        if let Body::Buffered { buflist } = &mut self.body {
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
    let frame = Frame::new(Frame::DATA_FRAME_TYPE, data)?;
    stream
        .try_stream_io(async |stream| Ok(stream.send_frame(frame).await?))
        .await
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
                let Some(field_section) = stream.read_header_frame().await.transpose()? else {
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
            match stream.read_data_frame_chunk().await.transpose()? {
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
                    match stream.read_data_frame_chunk().await.transpose()? {
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
            let Body::Buffered { buflist } = &mut self.body else {
                unreachable!("message body mode changed while reading buffered body")
            };
            buflist.write(body_part);
        }

        let Body::Buffered { buflist } = &mut self.body else {
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
                Body::Pending | Body::Buffered { .. } => {
                    self.read_buffered_body_from(stream).await?;
                }
                Body::Streaming { .. } => {
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
                let Some(field_section) = stream.read_header_frame().await.transpose()? else {
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
        B: Buf + Send + 's,
    {
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
        if matches!(self.body, Body::Pending) {
            self.body = Body::Buffered {
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
        Body::Pending => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        Body::Streaming { .. } => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        Body::Buffered { .. } => prepare_message_buffered_body_step(message, goal),
    }
}

fn prepare_message_buffered_body_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    let data = {
        let Body::Buffered { buflist } = &mut message.body else {
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
