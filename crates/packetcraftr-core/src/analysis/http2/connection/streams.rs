// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Message, MessageKind, Status};
use super::super::stream::{
    CLIENT, FieldRole, MsgBuild, Phase as StreamPhase, SERVER, StreamState, peer, validate,
};
use super::{ChainHead, Conn, Cx, Decoded, Evidence, Fault, Head, Phase, resources};
use crate::analysis::application;
use bytes::Bytes;

impl Conn {
    pub(crate) fn headers_block(
        &mut self,
        side: usize,
        stream_id: u32,
        head: ChainHead,
        decoded: Decoded,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        match head {
            ChainHead::Headers { end_stream } => {
                self.stream_headers(side, stream_id, end_stream, decoded, cx)
            }
            ChainHead::PushPromise { promised } => {
                self.push_promise(side, stream_id, promised, decoded, cx)
            }
        }
    }

    pub(crate) fn new_message(
        &mut self,
        stream_id: u32,
        kind: MessageKind,
        cx: &mut Cx<'_>,
    ) -> Result<MsgBuild, Error> {
        let index = cx.check_messages()?;
        let mut msg = MsgBuild::new(index, stream_id, kind);
        self.charge_conn(cx, resources::MESSAGE_OVERHEAD)?;
        msg.charged = resources::MESSAGE_OVERHEAD;
        Ok(msg)
    }

    fn msg_content_charge(msg: &MsgBuild) -> usize {
        msg.headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + msg
                .trailers
                .iter()
                .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
                .sum::<usize>()
            + msg.header_blocks.iter().map(Bytes::len).sum::<usize>()
            + msg
                .upgrade_head
                .as_ref()
                .map_or(0, |head| head.wire().len())
    }

    pub(crate) fn emit_message(
        &mut self,
        side: usize,
        mut build: MsgBuild,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let (cl_exempt, connect_cl_illegal) = match build.status_code {
            Some(status) => {
                let stream = self.streams.get(&build.stream_id);
                let method = stream.and_then(|s| s.method.as_deref());
                let connect = method == Some(b"CONNECT") && (200..300).contains(&status);
                (
                    method == Some(b"HEAD")
                        || status == 304
                        || (100..200).contains(&status)
                        || status == 204
                        || connect,
                    connect && build.content_length.is_some(),
                )
            }
            None => (false, false),
        };
        if connect_cl_illegal {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(build.stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "connect_content_length",
                    detail: "a CONNECT 2xx response must not carry content-length".into(),
                    wire: build.header_blocks.last().cloned().unwrap_or_default(),
                    sources: union_balanced(build.sets.clone())?,
                },
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        if status == Status::Complete
            && !cl_exempt
            && let Some(declared) = build.content_length
            && declared != build.body_bytes
        {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(build.stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "content_length_mismatch",
                    detail: "observed body length does not match content-length".into(),
                    wire: Bytes::new(),
                    sources: None,
                },
            )?;
            build.failure = build.failure.or(Some(Status::Malformed));
        }
        let status = build.failure.unwrap_or(status);
        let sources = union_balanced(std::mem::take(&mut build.sets))?.ok_or(
            Error::Application(application::Error::Sources {
                number: self.number,
            }),
        )?;
        let compression_sources = union_balanced(std::mem::take(&mut build.compression))?;
        self.release_conn(cx, build.charged);
        *cx.spans = cx
            .spans
            .checked_sub(build.charged_spans)
            .expect("msg spans");
        cx.charge_retained(
            Self::msg_content_charge(&build)
                + resources::EVENT_OVERHEAD
                + sources.frames().len() * resources::SPAN_OVERHEAD
                + compression_sources
                    .as_ref()
                    .map_or(0, |set| set.frames().len() * resources::SPAN_OVERHEAD),
        )?;
        cx.message(Message {
            index: build.index,
            stream: self.stream,
            generation: self.generation,
            http2_stream_id: build.stream_id,
            flow: self.dir_flow(side),
            kind: build.kind,
            request: build.request,
            promised_by: build.promised_by,
            status,
            headers: build.headers,
            trailers: build.trailers,
            header_blocks: build.header_blocks,
            upgrade_head: build.upgrade_head,
            body_bytes: build.body_bytes,
            sources,
            compression_sources,
        });
        Ok(())
    }

    pub(crate) fn begin_stream(
        &mut self,
        side: usize,
        stream_id: u32,
        evidence: Option<&Evidence>,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let initiator = if stream_id.is_multiple_of(2) {
            SERVER
        } else {
            CLIENT
        };
        if side != initiator {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "unpromised_stream",
                    detail: "HEADERS opened a stream the endpoint did not initiate".into(),
                    wire: evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                    sources: evidence.and_then(|e| e.sources.clone()),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        if initiator == CLIENT && stream_id <= self.max_initiated[CLIENT] {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "stream_id_not_monotonic",
                    detail: "a new client stream id did not exceed previously initiated ids".into(),
                    wire: evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                    sources: evidence.and_then(|e| e.sources.clone()),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        if initiator == CLIENT {
            self.max_initiated[CLIENT] = stream_id;
        }
        let open_count = self
            .streams
            .values()
            .filter(|stream| stream.phase != StreamPhase::Closed)
            .count();
        if open_count + 1 > cx.limits.max_active_streams
            || self.active[initiator] + 1 > cx.limits.max_active_streams
        {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Limit,
                    code: "active_streams",
                    detail: "concurrent streams exceed the configured bound".into(),
                    wire: evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                    sources: evidence.and_then(|e| e.sources.clone()),
                },
            )?;
            self.fail(cx, Status::Limit)?;
            return Ok(());
        }
        cx.check_streams()?;
        self.admitted_streams += 1;
        self.charge_conn(cx, resources::STREAM_OVERHEAD)?;
        let windows = [
            i64::from(self.settings[SERVER].acknowledged.initial_window_size),
            i64::from(self.settings[CLIENT].acknowledged.initial_window_size),
        ];
        let mut state = StreamState::open(initiator == CLIENT, windows);
        state.unprocessed = self.goaway[peer(initiator)].is_some_and(|last| stream_id > last);
        self.streams.insert(stream_id, state);
        self.active[initiator] += 1;
        let effective = self.settings[peer(initiator)]
            .acknowledged
            .max_concurrent_streams;
        if let Some(max) = effective
            && self.active[initiator] > max as usize
        {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Malformed,
                    code: "concurrent_streams",
                    detail: "open streams exceed the peer's acknowledged limit".into(),
                    wire: evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                    sources: evidence.and_then(|e| e.sources.clone()),
                },
            )?;
        }
        Ok(())
    }

    pub(crate) fn stream_headers(
        &mut self,
        side: usize,
        stream_id: u32,
        end_stream: bool,
        decoded: Decoded,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let Decoded {
            headers,
            block,
            sources: block_sources,
            compression,
        } = decoded;
        let client_initiated = !stream_id.is_multiple_of(2);
        let block_evidence = Evidence {
            wire: block.clone(),
            sources: block_sources.clone(),
        };
        if !self.streams.contains_key(&stream_id) {
            if self.closed.contains(&stream_id) {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "closed_stream_headers",
                        detail: "HEADERS arrived on a fully closed stream".into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
                return Ok(());
            }
            if side == CLIENT && client_initiated {
                self.begin_stream(side, stream_id, Some(&block_evidence), cx)?;
            } else {
                let (code, detail) = if side == SERVER && client_initiated {
                    (
                        "response_without_stream",
                        "the server sent HEADERS on a stream the client never opened",
                    )
                } else {
                    (
                        "unpromised_stream",
                        "HEADERS opened a stream the endpoint did not initiate",
                    )
                };
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code,
                        detail: detail.into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
        }
        let (role, new_head) = {
            let Some(stream) = self.streams.get(&stream_id) else {
                return Ok(());
            };
            match stream.phase {
                StreamPhase::Reserved => {
                    if side == SERVER {
                        (FieldRole::Response, true)
                    } else {
                        self.issue(
                            cx,
                            Fault {
                                flow: self.dir_flow(side),
                                http2_stream_id: Some(stream_id),
                                scope: IssueScope::Stream,
                                certainty: Certainty::Confirmed,
                                status: Status::Malformed,
                                code: "reserved_stream_headers",
                                detail: "a client sent HEADERS on a reserved stream".into(),
                                wire: block,
                                sources: block_sources,
                            },
                        )?;
                        self.fail(cx, Status::Malformed)?;
                        return Ok(());
                    }
                }
                StreamPhase::Open | StreamPhase::Closed => {
                    if stream.msgs[side].is_none() && !stream.ended[side] {
                        let head_role = if side == CLIENT {
                            FieldRole::Request
                        } else {
                            FieldRole::Response
                        };
                        (head_role, true)
                    } else {
                        (FieldRole::Trailer, false)
                    }
                }
            }
        };
        if matches!(self.phase, Phase::Dead) {
            return Ok(());
        }
        if let Some(stream) = self.streams.get_mut(&stream_id)
            && stream.phase == StreamPhase::Reserved
        {
            stream.phase = StreamPhase::Open;
            self.active[SERVER] += 1;
            let initiator = if stream.by_client { CLIENT } else { SERVER };
            let open = self
                .streams
                .values()
                .filter(|s| s.phase != StreamPhase::Closed)
                .count();
            let effective = self.settings[peer(initiator)]
                .acknowledged
                .max_concurrent_streams;
            if open > cx.limits.max_active_streams
                || effective.is_some_and(|max| self.active[initiator] > max as usize)
            {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Connection,
                        certainty: Certainty::ObservedOrder,
                        status: Status::Malformed,
                        code: "concurrent_streams",
                        detail: "a promised stream opened beyond the peer's concurrency".into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
            }
        }
        let mut failure = None;
        let meta = match validate(role, &headers) {
            Ok(meta) => meta,
            Err(detail) => {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "header_semantics",
                        detail: detail.into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
                failure = Some(Status::Malformed);
                Default::default()
            }
        };
        if role == FieldRole::Trailer && !end_stream {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "trailer_without_end_stream",
                    detail: "a trailer block must terminate the stream".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if let Some(status) = meta.status
            && (100..200).contains(&status)
            && end_stream
        {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "informational_end_stream",
                    detail: "a 1xx response must not end the stream".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if meta.protocol {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Unsupported,
                    code: "extended_connect",
                    detail: ":protocol extended CONNECT is outside this analyzer's semantics"
                        .into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            failure = failure.or(Some(Status::Unsupported));
        }
        if matches!(self.phase, Phase::Dead) {
            return Ok(());
        }
        if new_head {
            self.start_message(
                side,
                stream_id,
                Head {
                    role,
                    meta,
                    flawed: failure.is_some(),
                },
                Decoded {
                    headers,
                    block,
                    sources: block_sources,
                    compression,
                },
                cx,
            )?;
            if let Some(status) = failure
                && let Some(stream) = self.streams.get_mut(&stream_id)
                && let Some(msg) = stream.msgs[side].as_mut()
            {
                msg.failure = Some(status);
            }
        } else {
            let trailer_conflict = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| msg.trailers_seen);
            if trailer_conflict {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "second_trailer_block",
                        detail: "a third header block follows completed trailers".into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
            }
            let flawed = trailer_conflict || failure.is_some();
            let stream = self.streams.get_mut(&stream_id).expect("stream");
            if let Some(msg) = stream.msgs[side].as_mut() {
                if flawed {
                    msg.failure = Some(Status::Malformed);
                }
                msg.trailers_seen = true;
                let added = headers
                    .iter()
                    .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
                    .sum::<usize>()
                    + block.len();
                self.charge_conn(cx, added)?;
                let stream = self.streams.get_mut(&stream_id).expect("stream");
                if let Some(msg) = stream.msgs[side].as_mut() {
                    msg.charged += added;
                    msg.trailers.extend(headers);
                    msg.header_blocks.push(block);
                    if let Some(sources) = block_sources {
                        let frames = sources.frames().len();
                        let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
                        self.charge_conn(cx, charge)?;
                        cx.charge_spans(frames)?;
                        let msg = self
                            .streams
                            .get_mut(&stream_id)
                            .and_then(|s| s.msgs[side].as_mut())
                            .expect("msg");
                        msg.charged += charge;
                        msg.charged_spans += frames;
                        msg.sets.push(sources);
                    }
                    if let Some(set) = compression {
                        let frames = set.frames().len();
                        let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
                        self.charge_conn(cx, charge)?;
                        cx.charge_spans(frames)?;
                        let msg = self
                            .streams
                            .get_mut(&stream_id)
                            .and_then(|s| s.msgs[side].as_mut())
                            .expect("msg");
                        msg.charged += charge;
                        msg.charged_spans += frames;
                        msg.compression.push(set);
                    }
                }
            } else {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "headers_after_end",
                        detail: "HEADERS arrived after the sender already ended the stream".into(),
                        wire: block,
                        sources: block_sources,
                    },
                )?;
            }
        }
        if matches!(self.phase, Phase::Dead) {
            return Ok(());
        }
        if end_stream {
            self.end_side(side, stream_id, Status::Complete, cx)?;
        }
        Ok(())
    }

    pub(crate) fn start_message(
        &mut self,
        side: usize,
        stream_id: u32,
        head: Head,
        decoded: Decoded,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let Head { role, meta, flawed } = head;
        let Decoded {
            headers,
            block,
            sources: block_sources,
            compression,
        } = decoded;
        let kind = match role {
            FieldRole::Request => MessageKind::Request,
            FieldRole::Response => match meta.status {
                Some(status) if (100..200).contains(&status) => MessageKind::Informational,
                _ => MessageKind::Response,
            },
            FieldRole::Trailer => {
                return Err(Error::Application(application::Error::Sources {
                    number: self.number,
                }));
            }
        };
        let mut msg = self.new_message(stream_id, kind, cx)?;
        if flawed {
            msg.failure = Some(Status::Malformed);
        }
        let content_charge = headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + block.len();
        self.charge_conn(cx, content_charge)?;
        msg.charged += content_charge;
        msg.headers = headers;
        msg.header_blocks.push(block);
        msg.content_length = meta.content_length;
        msg.status_code = meta.status;
        if let Some(sources) = block_sources {
            let frames = sources.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(sources);
        }
        if let Some(set) = compression {
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.compression.push(set);
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if let Some(method) = meta.method {
            stream.method = Some(method);
        }
        if role == FieldRole::Request {
            stream.request = Some(msg.index);
        } else {
            msg.request = stream.request;
        }
        msg.promised_by = stream.promised_by;
        if let Some(status) = meta.status {
            let head_request = stream.method.as_deref() == Some(b"HEAD");
            stream.response_bodyless =
                head_request || (100..200).contains(&status) || status == 204 || status == 304;
        }
        let unprocessed = stream.unprocessed;
        if kind == MessageKind::Informational {
            self.emit_message(
                side,
                msg,
                if unprocessed {
                    Status::Unprocessed
                } else {
                    Status::Complete
                },
                cx,
            )?;
        } else {
            let stream = self.streams.get_mut(&stream_id).expect("stream");
            stream.msgs[side] = Some(msg);
        }
        Ok(())
    }

    pub(crate) fn end_side(
        &mut self,
        side: usize,
        stream_id: u32,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        stream.ended[side] = true;
        let unprocessed = stream.unprocessed;
        if let Some(msg) = stream.msgs[side].take() {
            self.emit_message(
                side,
                msg,
                if unprocessed {
                    Status::Unprocessed
                } else {
                    status
                },
                cx,
            )?;
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if stream.ended == [true, true] && stream.phase != StreamPhase::Closed {
            if stream.phase == StreamPhase::Open {
                let owner = if stream.by_client { CLIENT } else { SERVER };
                self.active[owner] = self.active[owner].saturating_sub(1);
            }
            stream.phase = StreamPhase::Closed;
            if stream.msgs.iter().all(Option::is_none) {
                self.streams.remove(&stream_id);
                self.closed.insert(stream_id);
                self.release_conn(cx, resources::STREAM_OVERHEAD - 64);
            }
        }
        Ok(())
    }

    pub(crate) fn push_promise(
        &mut self,
        side: usize,
        stream_id: u32,
        promised: u32,
        decoded: Decoded,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let Decoded {
            headers,
            block,
            sources: block_sources,
            compression,
        } = decoded;
        if side == CLIENT {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "client_push_promise",
                    detail: "a client sent PUSH_PROMISE".into(),
                    wire: block,
                    sources: block_sources,
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        if !self.settings[CLIENT].acknowledged.enable_push {
            let certainty = if self.settings[CLIENT].pending.is_empty() {
                Certainty::Confirmed
            } else {
                Certainty::ObservedOrder
            };
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty,
                    status: Status::Malformed,
                    code: "push_disabled",
                    detail: "PUSH_PROMISE while the client has push disabled".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
        }
        if promised.is_multiple_of(2) && promised > self.max_initiated[SERVER] {
            self.max_initiated[SERVER] = promised;
        } else {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "promised_stream_id",
                    detail: "PUSH_PROMISE names a reused or client-numbered stream".into(),
                    wire: block,
                    sources: block_sources,
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        let parent_open = self
            .streams
            .get(&stream_id)
            .is_some_and(|s| s.phase == StreamPhase::Open && s.by_client && !s.ended[SERVER]);
        if !parent_open {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "push_promise_closed_parent",
                    detail: "PUSH_PROMISE on a parent stream that cannot push".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
        }
        let meta = validate(FieldRole::Request, &headers);
        let mut msg = self.new_message(promised, MessageKind::PushPromise, cx)?;
        let content_charge = headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + block.len();
        self.charge_conn(cx, content_charge)?;
        msg.charged += content_charge;
        msg.headers = headers;
        msg.header_blocks.push(block);
        msg.promised_by = Some(stream_id);
        msg.request = self.streams.get(&stream_id).and_then(|s| s.request);
        if let Some(sources) = block_sources.clone() {
            let frames = sources.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(sources);
        }
        if let Some(set) = compression {
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(cx, charge)?;
            cx.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.compression.push(set);
        }
        if let Err(detail) = meta {
            msg.failure = Some(Status::Malformed);
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "push_promise_headers",
                    detail: detail.into(),
                    wire: Bytes::new(),
                    sources: block_sources,
                },
            )?;
        } else if let Ok(meta) = meta {
            msg.content_length = meta.content_length;
        }
        let index = msg.index;
        self.emit_message(SERVER, msg, Status::Complete, cx)?;
        let open_count = self
            .streams
            .values()
            .filter(|stream| stream.phase != StreamPhase::Closed)
            .count();
        if open_count + 1 > cx.limits.max_active_streams {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Limit,
                    code: "active_streams",
                    detail: "concurrent streams exceed the configured bound".into(),
                    wire: Bytes::new(),
                    sources: None,
                },
            )?;
            self.fail(cx, Status::Limit)?;
            return Ok(());
        }
        cx.check_streams()?;
        self.admitted_streams += 1;
        self.charge_conn(cx, resources::STREAM_OVERHEAD)?;
        let windows = [
            i64::from(self.settings[SERVER].acknowledged.initial_window_size),
            i64::from(self.settings[CLIENT].acknowledged.initial_window_size),
        ];
        let mut promised_stream = StreamState::reserved(stream_id, windows);
        promised_stream.request = Some(index);
        promised_stream.unprocessed = self.goaway[CLIENT].is_some_and(|last| promised > last);
        self.streams.insert(promised, promised_stream);
        Ok(())
    }

    pub(crate) fn reset_stream(
        &mut self,
        side: usize,
        stream_id: u32,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if !self.streams.contains_key(&stream_id) {
            if self.closed.contains(&stream_id) {
                return Ok(());
            }
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "reset_idle_stream",
                    detail: "RST_STREAM on a stream that was never opened".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            return Ok(());
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if stream.phase == StreamPhase::Closed && stream.ended == [true, true] {
            return Ok(());
        }
        let was_open = stream.phase == StreamPhase::Open;
        stream.phase = StreamPhase::Closed;
        stream.ended = [true, true];
        if was_open {
            let owner = if stream.by_client { CLIENT } else { SERVER };
            self.active[owner] = self.active[owner].saturating_sub(1);
        }
        for msg_side in [CLIENT, SERVER] {
            if let Some(msg) = self
                .streams
                .get_mut(&stream_id)
                .and_then(|s| s.msgs[msg_side].take())
            {
                self.emit_message(msg_side, msg, Status::Reset, cx)?;
            }
        }
        self.streams.remove(&stream_id);
        self.closed.insert(stream_id);
        self.release_conn(cx, resources::STREAM_OVERHEAD - 64);
        Ok(())
    }
}
