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
    pub(crate) fn opener_exhausted(&self, owner: usize) -> bool {
        self.clean_start
            && self.dirs[owner]
                .as_ref()
                .is_some_and(|dir| dir.fully_consumed_fin)
    }

    pub(crate) fn retain_pending_opener(
        &mut self,
        id: u32,
        code: &'static str,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if !self.pending_openers.contains_key(&id) {
            self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
            self.pending_openers.insert(id, code);
        }
        Ok(())
    }

    fn resolve_pending_opener(&mut self, id: u32, cx: &mut Cx<'_>) {
        if self.pending_openers.remove(&id).is_some() {
            self.release_conn(cx, resources::CLOSED_STREAM_OVERHEAD);
        }
    }

    pub(crate) fn reconcile_pending_openers(
        &mut self,
        owner: usize,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let mut fault = None;
        for (&id, &code) in &self.pending_openers {
            cx.check_deadline()?;
            if id.is_multiple_of(2) == (owner == SERVER) {
                fault = Some((id, code));
                break;
            }
        }
        if let Some((id, code)) = fault {
            self.issue(cx, Fault {
                flow: self.dir_flow(peer(owner)),
                http2_stream_id: Some(id),
                scope: IssueScope::Connection,
                certainty: Certainty::Confirmed,
                status: Status::Malformed,
                code,
                detail: "clean initiator FIN proves no opener exists; original frame evidence is retained in the earlier issue".into(),
                wire: Bytes::new(), sources: None,
            })?;
            self.fail(cx, Status::Malformed)?;
        }
        Ok(())
    }

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
        self.resolve_pending_opener(stream_id, cx);
        let early_response = self.early_response_headers.remove(&stream_id);
        if early_response.is_some() {
            self.release_conn(cx, resources::CLOSED_STREAM_OVERHEAD);
        } else {
            cx.check_streams()?;
            self.admitted_streams += 1;
        }
        self.charge_conn(cx, resources::STREAM_OVERHEAD)?;
        let windows = [
            i64::from(self.settings[SERVER].acknowledged.initial_window_size),
            i64::from(self.settings[CLIENT].acknowledged.initial_window_size),
        ];
        let mut state = StreamState::open(initiator == CLIENT, windows);
        state.early_response = early_response;
        state.ended[SERVER] = early_response.is_some_and(|early| early.ended);
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
        // without needing to infer whether prior streams remain open. A fully
        // consumed receiving FIN also rules out any hidden peer resets.
        let confirmed = receiver.pending.is_empty()
            && (max == 0
                || self.dirs[peer(initiator)]
                    .as_ref()
                    .is_some_and(|dir| dir.closed && dir.buffer.is_empty() && dir.chain.is_none()));
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
        let early = self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.early_response)
            .or_else(|| self.early_response_headers.get(&stream_id).copied());
        if side == SERVER
            && let Some(early) = early
            && self.early_response_followup(
                stream_id,
                early,
                &headers,
                end_stream,
                &block_evidence,
                cx,
            )?
        {
            return Ok(());
        }
        if !self.streams.contains_key(&stream_id) {
            if self
                .closed
                .get(&stream_id)
                .is_some_and(|closed| closed.reset_by == Some(peer(side)) && !closed.ended[side])
            {
                // The peer's HEADERS may have been in flight when we observed the
                // reset. HPACK has already been decoded to preserve table state.
                return Ok(());
            }
            if self.closed.contains_key(&stream_id)
                || stream_id <= self.max_initiated[if client_initiated { CLIENT } else { SERVER }]
            {
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
                    && !self.opener_exhausted(CLIENT)
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
                if delayed_opener {
                    self.retain_pending_opener(stream_id, code, cx)?;
                }
                if delayed_opener && !self.early_response_headers.contains_key(&stream_id) {
                    cx.check_streams()?;
                    self.admitted_streams += 1;
                    self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
                    self.early_response_headers
                        .insert(stream_id, Default::default());
                }
                if delayed_opener {
                    let validation = validate(FieldRole::Response, &headers).and_then(|meta| {
                        if end_stream
                            && meta
                                .status
                                .is_some_and(|status| (100..200).contains(&status))
                        {
                            Err("a 1xx response must not end the stream")
                        } else {
                            Ok(meta)
                        }
                    });
                    match validation {
                        Ok(meta) => {
                            let early = self
                                .early_response_headers
                                .get_mut(&stream_id)
                                .expect("early response");
                            early.final_seen = meta
                                .status
                                .is_none_or(|status| !(100..200).contains(&status));
                            early.forbids_trailers = matches!(meta.status, Some(204 | 304));
                            early.ended = end_stream || malformed;
                        }
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
                            // Reject further response activity while retaining the
                            // capture-delayed request's admission and evidence.
                            self.early_response_headers
                                .get_mut(&stream_id)
                                .expect("early response")
                                .ended = true;
                        }
                    }
                }
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
                                scope: IssueScope::Connection,
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
        if role == FieldRole::Trailer
            && self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| matches!(msg.status_code, Some(204 | 304)))
        {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "header_semantics",
                    detail: "204 and 304 responses cannot contain trailers".into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            failure = Some(Status::Malformed);
        }
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

    fn early_response_followup(
        &mut self,
        id: u32,
        early: super::super::stream::EarlyResponse,
        headers: &[super::super::model::Header],
        end_stream: bool,
        evidence: &Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        if !early.final_seen && !early.ended {
            return Ok(false);
        }
        let invalid = early.ended
            || early.forbids_trailers
            || !end_stream
            || validate(FieldRole::Trailer, headers).is_err();
        self.issue(cx, Fault {
            flow: self.dir_flow(SERVER), http2_stream_id: Some(id), scope: IssueScope::Stream,
            certainty: if invalid { Certainty::Confirmed } else { Certainty::Indeterminate },
            status: if invalid { Status::Malformed } else { Status::Incomplete },
            code: if early.ended { "headers_after_end" } else if invalid { "header_semantics" } else { "early_response_trailers" },
            detail: "HEADERS follow a previously observed final response whose opener was capture-delayed".into(),
            wire: evidence.wire.clone(), sources: evidence.sources.clone(),
        })?;
        if self.streams.contains_key(&id) {
            // The provisional response has no message builder to emit. Its
            // error must not terminate the independently captured request.
            self.end_side(
                SERVER,
                id,
                if invalid {
                    Status::Malformed
                } else {
                    Status::Incomplete
                },
                cx,
            )?;
        } else if let Some(state) = self.early_response_headers.get_mut(&id) {
            state.ended = true;
        }
        Ok(true)
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
        if role == FieldRole::Request {
            self.release_parent_promises(stream_id, cx)?;
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

    pub(crate) fn stream_window_overflows(
        &self,
        side: usize,
        stream_id: u32,
        cx: &Cx<'_>,
    ) -> Result<bool, Error> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Ok(false);
        };
        let granted = stream.window_granted[side];
        let base = stream.send_window[side].saturating_sub(granted);
        let mut previous_grants = 0;
        let mut delta = 0i64;
        let mut overflow = base > super::super::settings::WINDOW_MAX;
        // A WINDOW_UPDATE is received after every preceding SETTINGS in the
        // granting direction. Later decreases cannot repair an earlier overflow.
        // Unacknowledged increases cannot establish receipt; only a nonpositive
        // cumulative delta lowers the bound. ACKed increases are already in base.
        // Subtracting all observed DATA makes each intermediate bound conservative.
        for pending in &self.settings[peer(side)].pending {
            cx.check_deadline()?;
            let before = pending.window_grants.get(&stream_id).copied().unwrap_or(0);
            if before > previous_grants {
                overflow |= base.saturating_add(before).saturating_add(delta.min(0))
                    > super::super::settings::WINDOW_MAX;
            }
            previous_grants = before;
            delta = delta.saturating_add(pending.window_delta);
        }
        if granted > previous_grants || self.settings[peer(side)].pending.is_empty() {
            overflow |= stream.send_window[side].saturating_add(delta.min(0))
                > super::super::settings::WINDOW_MAX;
        }
        Ok(overflow)
    }

    pub(crate) fn confirm_stream_window_overflow(
        &mut self,
        side: usize,
        stream_id: u32,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        if self.stream_window_overflows(side, stream_id, cx)? {
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
            self.close_stream(stream_id, Status::Malformed, None, cx)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn end_side(
        &mut self,
        side: usize,
        stream_id: u32,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete && self.confirm_stream_window_overflow(side, stream_id, cx)? {
            return Ok(());
        }
        let defer_complete = status == Status::Complete
            && (self.waiting_settings_ack(CLIENT) || self.waiting_settings_ack(SERVER));
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        stream.ended[side] = true;
        if side == SERVER
            && let Some(early) = stream.early_response.as_mut()
        {
            early.ended = true;
        }
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
                self.retain_closed_credit(stream_id, cx)?;
                self.streams.remove(&stream_id);
                self.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        ended: [true, true],
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
        let promised_reset_in_flight = self
            .closed
            .get(&promised)
            .is_some_and(|closed| closed.reset_by == Some(CLIENT) && !closed.ended[SERVER]);
        if promised.is_multiple_of(2)
            && promised > self.max_initiated[SERVER]
            && (!self.closed.contains_key(&promised) || promised_reset_in_flight)
        {
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
        self.resolve_pending_opener(promised, cx);
        let parent_open = self
            .streams
            .get(&stream_id)
            .is_some_and(|s| s.phase == StreamPhase::Open && s.by_client && !s.ended[SERVER]);
        // A peer promise may have been sent before it received our reset.
        // RFC 9113 §5.1 still requires HPACK processing and stream reservation.
        let in_flight_after_reset = self
            .closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(peer(side)) && !closed.ended[side]);
        let delayed_parent = !self.opener_exhausted(CLIENT)
            && !stream_id.is_multiple_of(2)
            && stream_id > self.max_initiated[CLIENT]
            && !self.streams.contains_key(&stream_id)
            && !self.closed.contains_key(&stream_id)
            && !self
                .early_response_headers
                .get(&stream_id)
                .is_some_and(|early| early.ended);
        if !parent_open && !in_flight_after_reset && !delayed_parent {
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
        if delayed_parent && !rejected {
            self.retain_early_parent(stream_id, cx)?;
            self.charge_conn(cx, resources::PENDING_OVERHEAD)?;
            self.parent_deferred.push_back(msg);
        } else {
            self.emit_message(SERVER, msg, Status::Complete, cx)?;
        }
        if promised_reset_in_flight {
            // The promise can precede receipt of a peer reset, but must not
            // revive the reset stream or emit later in-flight response messages.
            return Ok(());
        }
        if rejected {
            cx.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
            self.closed.insert(
                promised,
                super::ClosedStream {
                    ended: [true, true],
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

    // A peer's terminal event may precede the captured opener. Preserve its
    // direction without discarding the opener's independently valid evidence.
    pub(crate) fn reject_priority_stream(
        &mut self,
        side: usize,
        id: u32,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if self.streams.contains_key(&id) {
            return self.close_stream(id, Status::Malformed, None, cx);
        }
        let owner = if id.is_multiple_of(2) { SERVER } else { CLIENT };
        if self.closed.contains_key(&id) || id <= self.max_initiated[owner] {
            return Ok(());
        }
        if side == SERVER && owner == CLIENT {
            self.retain_early_parent(id, cx)?;
            self.early_response_headers
                .get_mut(&id)
                .expect("early parent")
                .ended = true;
        } else {
            cx.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
            self.closed.insert(
                id,
                super::ClosedStream {
                    ended: [true, true],
                    reset_by: None,
                    request: None,
                },
            );
        }
        Ok(())
    }

    fn retain_early_parent(&mut self, id: u32, cx: &mut Cx<'_>) -> Result<(), Error> {
        if !self.early_response_headers.contains_key(&id) {
            cx.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
            self.early_response_headers.insert(id, Default::default());
        }
        Ok(())
    }

    fn release_parent_promises(&mut self, id: u32, cx: &mut Cx<'_>) -> Result<(), Error> {
        let count = self.parent_deferred.len();
        let request = self.streams.get(&id).and_then(|stream| stream.request);
        for _ in 0..count {
            cx.check_deadline()?;
            let mut msg = self.parent_deferred.pop_front().expect("pending promise");
            if msg.promised_by == Some(id) {
                self.release_conn(cx, resources::PENDING_OVERHEAD);
                msg.request = request;
                self.emit_message(SERVER, msg, Status::Complete, cx)?;
            } else {
                self.parent_deferred.push_back(msg);
            }
        }
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
            let confirmed = self.clean_start && (side == owner || self.opener_exhausted(owner));
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
            } else if side == SERVER && owner == CLIENT {
                self.retain_pending_opener(stream_id, "reset_idle_stream", cx)?;
                self.retain_early_parent(stream_id, cx)?;
                self.early_response_headers
                    .get_mut(&stream_id)
                    .expect("early parent")
                    .ended = true;
            } else {
                self.retain_pending_opener(stream_id, "reset_idle_stream", cx)?;
                cx.check_streams()?;
                self.admitted_streams += 1;
                self.charge_conn(cx, resources::CLOSED_STREAM_OVERHEAD)?;
                self.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        ended: [side == CLIENT, side == SERVER],
                        reset_by: Some(side),
                        request: None,
                    },
                );
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
        if stream.phase == StreamPhase::Closed
            && stream.ended == [true, true]
            && stream.msgs.iter().all(Option::is_none)
        {
            return Ok(());
        }
        let mut ended = stream.ended;
        if let Some(side) = reset_by {
            ended[side] = true;
        } else {
            ended = [true, true];
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
        self.retain_closed_credit(stream_id, cx)?;
        self.streams.remove(&stream_id);
        self.closed.insert(
            stream_id,
            super::ClosedStream {
                ended,
                reset_by,
                request,
            },
        );
        self.release_conn(
            cx,
            resources::STREAM_OVERHEAD - resources::CLOSED_STREAM_OVERHEAD,
        );
        Ok(())
    }
}
