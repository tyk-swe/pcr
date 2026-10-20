// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Request, response, and trailer semantics for decoded stream headers.

use super::super::{
    ChainHead, ConnectionState, Context, Decoded, Evidence, Fault, Head, Phase, resources,
};
use crate::analysis::http2::Error;
use crate::analysis::http2::headers::{FieldRole, validate};
use crate::analysis::http2::model::{Certainty, IssueScope, Status};
use crate::analysis::http2::stream::{CLIENT, Phase as StreamPhase, SERVER, peer};

const RESPONSE_AFTER_GOAWAY: &str =
    "the server responded on a client stream above its own GOAWAY last_stream_id";

impl ConnectionState {
    pub(crate) fn headers_block(
        &mut self,
        side: usize,
        stream_id: u32,
        head: ChainHead,
        decoded: Decoded,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        match head {
            ChainHead::Headers {
                end_stream,
                malformed,
            } => {
                self.stream_headers(side, stream_id, end_stream, malformed, decoded, context)?;
                if malformed
                    && !matches!(self.phase, Phase::Dead)
                    && self.streams.contains_key(&stream_id)
                {
                    self.close_stream(stream_id, Status::Malformed, None, context)?;
                }
                Ok(())
            }
            ChainHead::PushPromise { promised } => {
                self.push_promise(side, stream_id, promised, decoded, context)
            }
        }
    }

    pub(crate) fn stream_headers(
        &mut self,
        side: usize,
        stream_id: u32,
        end_stream: bool,
        malformed: bool,
        decoded: Decoded,
        context: &mut Context<'_>,
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
                context,
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
                    context,
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
                self.begin_stream(side, stream_id, Some(&block_evidence), context)?;
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
                    context,
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
                    self.retain_pending_opener(stream_id, code, context)?;
                }
                if delayed_opener && !self.early_response_headers.contains_key(&stream_id) {
                    context.check_streams()?;
                    self.admitted_streams += 1;
                    self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
                    self.early_response_headers
                        .insert(stream_id, Default::default());
                }
                if delayed_opener {
                    // The server's own ordered bytes place this response after
                    // its GOAWAY, which promised the stream was not processed.
                    let above_goaway = self.goaway[SERVER].is_some_and(|last| stream_id > last);
                    let validation = validate(FieldRole::Response, &headers)
                        .map_err(|detail| ("header_semantics", detail))
                        .and_then(|meta| {
                            if end_stream
                                && meta
                                    .status
                                    .is_some_and(|status| (100..200).contains(&status))
                            {
                                Err(("header_semantics", "a 1xx response must not end the stream"))
                            } else if above_goaway {
                                Err(("response_after_goaway", RESPONSE_AFTER_GOAWAY))
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
                            early.bodyless = matches!(meta.status, Some(204 | 205 | 304));
                            early.ended = end_stream || malformed;
                        }
                        Err((code, detail)) => {
                            self.issue(
                                context,
                                Fault {
                                    flow: self.dir_flow(side),
                                    http2_stream_id: Some(stream_id),
                                    scope: IssueScope::Stream,
                                    certainty: Certainty::Confirmed,
                                    status: Status::Malformed,
                                    code,
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
                    self.fail(context, Status::Malformed)?;
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
                context,
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
            return self.close_stream(stream_id, Status::Malformed, None, context);
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
                            context,
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
                        self.fail(context, Status::Malformed)?;
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
            if self.enforce_concurrency(SERVER, stream_id, Some(&block_evidence), context)? {
                return Ok(());
            }
        }
        let mut failure = malformed.then_some(Status::Malformed);
        let meta = match validate(role, &headers) {
            Ok(meta) => meta,
            Err(detail) => {
                self.issue(
                    context,
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
                super::super::super::headers::Meta {
                    method: if role == FieldRole::Request {
                        super::super::super::headers::request_method(&headers)
                    } else {
                        None
                    },
                    status: if role == FieldRole::Response {
                        super::super::super::headers::response_status(&headers)
                    } else {
                        None
                    },
                    ..Default::default()
                }
            }
        };
        if side == SERVER
            && role == FieldRole::Response
            && client_initiated
            && self.goaway[SERVER].is_some_and(|last| stream_id > last)
        {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "response_after_goaway",
                    detail: RESPONSE_AFTER_GOAWAY.into(),
                    wire: block.clone(),
                    sources: block_sources.clone(),
                },
            )?;
            failure = Some(Status::Malformed);
        }
        if role == FieldRole::Trailer
            && self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| matches!(msg.status_code, Some(204 | 304)))
        {
            self.issue(
                context,
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
                context,
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
                context,
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
                context,
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
                context,
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
                    context,
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
                self.charge_conn(context, added)?;
                let stream = self.streams.get_mut(&stream_id).expect("stream");
                if let Some(msg) = stream.msgs[side].as_mut() {
                    msg.charged += added;
                    msg.trailers.extend(headers);
                    msg.header_blocks.push(block);
                    if let Some(sources) = block_sources {
                        let frames = sources.frames().len();
                        let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
                        self.charge_conn(context, charge)?;
                        context.charge_spans(frames)?;
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
                        self.charge_conn(context, charge)?;
                        context.charge_spans(frames)?;
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
                    context,
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
            self.close_stream(stream_id, Status::Malformed, None, context)?;
        } else if end_stream {
            self.end_side(side, stream_id, Status::Complete, context)?;
        }
        Ok(())
    }

    fn early_response_followup(
        &mut self,
        id: u32,
        early: super::super::super::stream::EarlyResponse,
        headers: &[super::super::super::model::Header],
        end_stream: bool,
        evidence: &Evidence,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if !early.final_seen && !early.ended {
            return Ok(false);
        }
        let invalid = early.ended
            || early.forbids_trailers
            || !end_stream
            || validate(FieldRole::Trailer, headers).is_err();
        self.issue(context, Fault {
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
                context,
            )?;
        } else if let Some(state) = self.early_response_headers.get_mut(&id) {
            state.ended = true;
        }
        Ok(true)
    }
}
