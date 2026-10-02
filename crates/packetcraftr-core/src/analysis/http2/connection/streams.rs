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
            ChainHead::Headers {
                end_stream,
                malformed,
            } => {
                self.stream_headers(side, stream_id, end_stream, malformed, decoded, cx)?;
                if malformed
                    && !matches!(self.phase, Phase::Dead)
                    && self.streams.contains_key(&stream_id)
                {
                    self.close_stream(stream_id, Status::Malformed, None, cx)?;
                }
                Ok(())
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
        build: MsgBuild,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete
            && (self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER))
        {
            self.charge_conn(cx, resources::PENDING_OVERHEAD)?;
            self.ack_deferred.push_back((side, build, status));
            return Ok(());
        }
        self.emit_message_with_completion(side, build, status, status == Status::Complete, cx)
            .map(|_| ())
    }

    fn emit_message_with_completion(
        &mut self,
        side: usize,
        mut build: MsgBuild,
        status: Status,
        complete: bool,
        cx: &mut Cx<'_>,
    ) -> Result<Status, Error> {
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
        if complete
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
                + resources::MESSAGE_OVERHEAD
                + resources::SET_OVERHEAD
                + sources.frames().len() * resources::SPAN_OVERHEAD
                + compression_sources.as_ref().map_or(0, |set| {
                    resources::SET_OVERHEAD + set.frames().len() * resources::SPAN_OVERHEAD
                }),
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
        Ok(status)
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
        self.enforce_concurrency(initiator, stream_id, evidence, cx)?;
        Ok(())
    }

    fn enforce_concurrency(
        &mut self,
        initiator: usize,
        stream_id: u32,
        evidence: Option<&Evidence>,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        let receiver = &self.settings[peer(initiator)];
        let Some(max) = receiver.acknowledged.max_concurrent_streams else {
            return Ok(false);
        };
        if self.active[initiator] <= max as usize {
            return Ok(false);
        }
        // Any existing stream might already have been reset by the peer in
        // the other capture direction. Only a zero limit proves rejection
        // without needing to infer whether prior streams remain open.
        let confirmed = receiver.pending.is_empty() && max == 0;
        self.issue(
            cx,
            Fault {
                flow: self.dir_flow(initiator),
                http2_stream_id: Some(stream_id),
                scope: IssueScope::Stream,
                certainty: if confirmed {
                    Certainty::Confirmed
                } else {
                    Certainty::ObservedOrder
                },
                status: Status::Malformed,
                code: "concurrent_streams",
                detail: "open streams exceed the peer's acknowledged limit".into(),
                wire: evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                sources: evidence.and_then(|e| e.sources.clone()),
            },
        )?;
        if confirmed {
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
        }
        Ok(confirmed)
    }

    pub(crate) fn stream_headers(
        &mut self,
        side: usize,
        stream_id: u32,
        end_stream: bool,
        malformed: bool,
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
            if self
                .closed
                .get(&stream_id)
                .is_some_and(|closed| closed.reset_by == Some(peer(side)))
            {
                // The peer's HEADERS may have been in flight when we observed the
                // reset. HPACK has already been decoded to preserve table state.
                return Ok(());
            }
            if self.closed.contains_key(&stream_id) {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Stream,
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
                let delayed_opener = side == SERVER
                    && client_initiated
                    && (!self.clean_start || stream_id > self.max_initiated[CLIENT]);
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(stream_id),
                        scope: IssueScope::Connection,
                        certainty: if delayed_opener {
                            Certainty::Indeterminate
                        } else {
                            Certainty::Confirmed
                        },
                        status: if delayed_opener {
                            Status::Incomplete
                        } else {
                            Status::Malformed
                        },
                        code,
                        detail: detail.into(),
                        wire: block.clone(),
                        sources: block_sources.clone(),
                    },
                )?;
                // Keep the bounded, sourced header-block evidence without inventing
                // request correlation. A delayed client opener can still be admitted.
                if !delayed_opener {
                    self.fail(cx, Status::Malformed)?;
                }
                return Ok(());
            }
        }
        if self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| stream.phase != StreamPhase::Reserved && stream.ended[side])
        {
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
            return self.close_stream(stream_id, Status::Malformed, None, cx);
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
            if self.enforce_concurrency(SERVER, stream_id, Some(&block_evidence), cx)? {
                return Ok(());
            }
        }
        let mut failure = malformed.then_some(Status::Malformed);
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
                super::super::stream::Meta {
                    method: if role == FieldRole::Request {
                        super::super::stream::request_method(&headers)
                    } else {
                        None
                    },
                    status: if role == FieldRole::Response {
                        super::super::stream::response_status(&headers)
                    } else {
                        None
                    },
                    ..Default::default()
                }
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
            if trailer_conflict {
                failure = Some(Status::Malformed);
            }
            let flawed = failure.is_some();
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
                failure = Some(Status::Malformed);
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
        if failure == Some(Status::Malformed) {
            // Preserve the decoded field section before applying its stream error.
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
        } else if end_stream {
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
                head_request || (100..200).contains(&status) || matches!(status, 204 | 205 | 304);
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

    pub(crate) fn release_ack_deferred_messages(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
        if self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER) {
            return Ok(());
        }
        let immediate = std::mem::take(&mut self.ack_deferred);
        self.release_conn(cx, immediate.len() * resources::PENDING_OVERHEAD);
        for (side, msg, status) in immediate {
            cx.check_deadline()?;
            self.emit_message(side, msg, status, cx)?;
        }
        let scratch = self
            .streams
            .len()
            .saturating_mul(2 * size_of::<(usize, u32)>());
        cx.charge_live(scratch)?;
        let result = (|| {
            let mut completed = Vec::with_capacity(self.streams.len().saturating_mul(2));
            for (id, stream) in &self.streams {
                cx.check_deadline()?;
                for side in [CLIENT, SERVER] {
                    if stream.ended[side] && stream.msgs[side].is_some() {
                        completed.push((side, *id));
                    }
                }
            }
            for (side, id) in completed {
                cx.check_deadline()?;
                self.end_side(side, id, Status::Complete, cx)?;
            }
            Ok(())
        })();
        cx.release_live(scratch);
        result
    }

    pub(crate) fn end_side(
        &mut self,
        side: usize,
        stream_id: u32,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete
            && self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.send_window[side] > super::super::settings::WINDOW_MAX)
        {
            self.issue(cx, Fault {
                flow: self.dir_flow(side),
                http2_stream_id: Some(stream_id),
                scope: IssueScope::Stream,
                certainty: Certainty::Confirmed,
                status: Status::Malformed,
                code: "stream_window_overflow",
                detail: "stream flow window remains above 2^31-1 after the sender ended; earlier WINDOW_UPDATE evidence is retained".into(),
                wire: Bytes::new(),
                sources: None,
            })?;
            return self.close_stream(stream_id, Status::Malformed, None, cx);
        }
        let defer_complete = status == Status::Complete
            && (self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER));
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        stream.ended[side] = true;
        let unprocessed = stream.unprocessed;
        if !defer_complete && let Some(msg) = stream.msgs[side].take() {
            let emitted = self.emit_message_with_completion(
                side,
                msg,
                if unprocessed {
                    Status::Unprocessed
                } else {
                    status
                },
                status == Status::Complete,
                cx,
            )?;
            if emitted == Status::Malformed {
                return self.close_stream(stream_id, Status::Malformed, None, cx);
            }
        }
        let stream = self.streams.get_mut(&stream_id).expect("stream");
        if stream.ended == [true, true] {
            if stream.phase == StreamPhase::Open {
                let owner = if stream.by_client { CLIENT } else { SERVER };
                self.active[owner] = self.active[owner].saturating_sub(1);
            }
            stream.phase = StreamPhase::Closed;
            if stream.msgs.iter().all(Option::is_none) {
                let request = stream.request;
                self.streams.remove(&stream_id);
                self.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        reset_by: None,
                        request,
                    },
                );
                self.release_conn(
                    cx,
                    resources::STREAM_OVERHEAD - resources::CLOSED_STREAM_OVERHEAD,
                );
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
                    scope: IssueScope::Connection,
                    certainty,
                    status: Status::Malformed,
                    code: "push_disabled",
                    detail: "PUSH_PROMISE while the client has push disabled".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            if certainty == Certainty::Confirmed {
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
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
        // A peer promise may have been sent before it received our reset.
        // RFC 9113 §5.1 still requires HPACK processing and stream reservation.
        let in_flight_after_reset = self
            .closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(peer(side)));
        if !parent_open && !in_flight_after_reset {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "push_promise_closed_parent",
                    detail: "PUSH_PROMISE on a parent stream that cannot push".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        let meta = validate(FieldRole::Request, &headers).and_then(|meta| {
            if !matches!(meta.method.as_deref(), Some(b"GET" | b"HEAD")) {
                return Err("a pushed request must use a known safe and cacheable method");
            }
            if meta.content_length.is_some_and(|length| length != 0) {
                return Err("a pushed request must not indicate request content");
            }
            Ok(meta)
        });
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
        msg.request = self
            .streams
            .get(&stream_id)
            .and_then(|s| s.request)
            .or_else(|| self.closed.get(&stream_id).and_then(|s| s.request));
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
        let rejected = meta.is_err();
        let mut promised_method = None;
        if let Err(detail) = meta {
            msg.failure = Some(Status::Malformed);
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(promised),
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
            promised_method = meta.method;
        }
        let index = msg.index;
        self.emit_message(SERVER, msg, Status::Complete, cx)?;
        if rejected {
            cx.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
            self.closed.insert(
                promised,
                super::ClosedStream {
                    reset_by: None,
                    request: Some(index),
                },
            );
            return Ok(());
        }
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
                    http2_stream_id: Some(promised),
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
        promised_stream.method = promised_method;
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
            let owner = if stream_id.is_multiple_of(2) {
                SERVER
            } else {
                CLIENT
            };
            if self.closed.contains_key(&stream_id) || stream_id <= self.max_initiated[owner] {
                return Ok(());
            }
            let confirmed = self.clean_start && side == owner;
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: if confirmed {
                        Certainty::Confirmed
                    } else {
                        Certainty::Indeterminate
                    },
                    status: if confirmed {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    code: "reset_idle_stream",
                    detail: "RST_STREAM on a stream that was never opened".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if confirmed {
                self.fail(cx, Status::Malformed)?;
            }
            return Ok(());
        }
        self.close_stream(stream_id, Status::Reset, Some(side), cx)
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: u32,
        status: Status,
        reset_by: Option<usize>,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
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
                self.emit_message(msg_side, msg, status, cx)?;
            }
        }
        let request = self.streams.get(&stream_id).and_then(|s| s.request);
        self.streams.remove(&stream_id);
        self.closed
            .insert(stream_id, super::ClosedStream { reset_by, request });
        self.release_conn(
            cx,
            resources::STREAM_OVERHEAD - resources::CLOSED_STREAM_OVERHEAD,
        );
        Ok(())
    }
}
