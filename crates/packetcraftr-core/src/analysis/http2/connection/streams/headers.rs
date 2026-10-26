// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Request, response, and trailer semantics for decoded stream headers.

use super::super::{ChainHead, ConnectionState, Context, Decoded, Evidence, Fault, Head, Phase};
use crate::analysis::http2::Error;
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::headers::{FieldRole, validate};
use crate::analysis::http2::model::{Certainty, IssueScope, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::Phase as StreamPhase;

const RESPONSE_AFTER_GOAWAY: &str =
    "the server responded on a client stream above its own GOAWAY last_stream_id";

impl ConnectionState {
    pub(crate) fn headers_block(
        &mut self,
        side: Side,
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
                    && self.streams.open.contains_key(&stream_id)
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
        side: Side,
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
        let client_initiated = Side::initiator_of(stream_id) == Side::Client;
        let block_evidence = Evidence {
            wire: block.clone(),
            sources: block_sources.clone(),
        };
        let early = self
            .streams
            .open
            .get(&stream_id)
            .and_then(|stream| stream.early_response)
            .or_else(|| self.streams.early_responses.get(&stream_id).copied());
        if side == Side::Server
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
        if !self.streams.open.contains_key(&stream_id) {
            if self
                .streams
                .closed
                .get(&stream_id)
                .is_some_and(|closed| closed.reset_by == Some(side.peer()) && !closed.ended[side])
            {
                // The peer's HEADERS may have been in flight when we observed the
                // reset. HPACK has already been decoded to preserve table state.
                return Ok(());
            }
            if self.streams.closed.contains_key(&stream_id)
                || stream_id
                    <= self.streams.max_initiated[if client_initiated {
                        Side::Client
                    } else {
                        Side::Server
                    }]
            {
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::ClosedStreamHeaders,
                        "HEADERS arrived on a fully closed stream",
                    )
                    .stream(Some(stream_id))
                    .evidence(block.clone(), block_sources.clone()),
                )?;
                return Ok(());
            }
            if side == Side::Client && client_initiated {
                self.begin_stream(side, stream_id, Some(&block_evidence), context)?;
            } else {
                let (code, detail) = if side == Side::Server && client_initiated {
                    (
                        IssueCode::ResponseWithoutStream,
                        "the server sent HEADERS on a stream the client never opened",
                    )
                } else {
                    (
                        IssueCode::UnpromisedStream,
                        "HEADERS opened a stream the endpoint did not initiate",
                    )
                };
                let delayed_opener = side == Side::Server
                    && client_initiated
                    && !self.opener_exhausted(Side::Client)
                    && (!self.clean_start || stream_id > self.streams.max_initiated[Side::Client]);
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Connection,
                        if delayed_opener {
                            Status::Incomplete
                        } else {
                            Status::Malformed
                        },
                        code,
                        detail,
                    )
                    .stream(Some(stream_id))
                    .certainty(if delayed_opener {
                        Certainty::Indeterminate
                    } else {
                        Certainty::Confirmed
                    })
                    .evidence(block.clone(), block_sources.clone()),
                )?;
                if delayed_opener {
                    self.retain_pending_opener(stream_id, code, context)?;
                }
                if delayed_opener && !self.streams.early_responses.contains_key(&stream_id) {
                    context.check_streams()?;
                    self.streams.admitted += 1;
                    context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
                    self.streams
                        .early_responses
                        .insert(stream_id, Default::default());
                }
                if delayed_opener {
                    // The server's own ordered bytes place this response after
                    // its GOAWAY, which promised the stream was not processed.
                    let above_goaway =
                        self.control.goaway[Side::Server].is_some_and(|last| stream_id > last);
                    let validation = validate(FieldRole::Response, &headers)
                        .map_err(|detail| (IssueCode::HeaderSemantics, detail))
                        .and_then(|meta| {
                            if end_stream
                                && meta
                                    .status
                                    .is_some_and(|status| (100..200).contains(&status))
                            {
                                Err((
                                    IssueCode::HeaderSemantics,
                                    "a 1xx response must not end the stream",
                                ))
                            } else if above_goaway {
                                Err((IssueCode::ResponseAfterGoaway, RESPONSE_AFTER_GOAWAY))
                            } else {
                                Ok(meta)
                            }
                        });
                    match validation {
                        Ok(meta) => {
                            let early = self
                                .streams
                                .early_responses
                                .get_mut(&stream_id)
                                .ok_or(Error::Invariant("early response"))?;
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
                                Fault::new(
                                    self.dir_flow(side),
                                    IssueScope::Stream,
                                    Status::Malformed,
                                    code,
                                    detail,
                                )
                                .stream(Some(stream_id))
                                .evidence(block.clone(), block_sources.clone()),
                            )?;
                            // Reject further response activity while retaining the
                            // capture-delayed request's admission and evidence.
                            self.streams
                                .early_responses
                                .get_mut(&stream_id)
                                .ok_or(Error::Invariant("early response"))?
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
            .open
            .get(&stream_id)
            .is_some_and(|stream| stream.phase != StreamPhase::Reserved && stream.ended[side])
        {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::HeadersAfterEnd,
                    "HEADERS arrived after the sender already ended the stream",
                )
                .stream(Some(stream_id))
                .evidence(block, block_sources),
            )?;
            return self.close_stream(stream_id, Status::Malformed, None, context);
        }
        let (role, new_head) = {
            let Some(stream) = self.streams.open.get(&stream_id) else {
                return Ok(());
            };
            match stream.phase {
                StreamPhase::Reserved => {
                    if side == Side::Server {
                        (FieldRole::Response, true)
                    } else {
                        self.reject(
                            context,
                            Fault::new(
                                self.dir_flow(side),
                                IssueScope::Connection,
                                Status::Malformed,
                                IssueCode::ReservedStreamHeaders,
                                "a client sent HEADERS on a reserved stream",
                            )
                            .stream(Some(stream_id))
                            .evidence(block, block_sources),
                        )?;
                        return Ok(());
                    }
                }
                StreamPhase::Open | StreamPhase::Closed => {
                    if stream.msgs[side].is_none() && !stream.ended[side] {
                        let head_role = if side == Side::Client {
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
        if let Some(stream) = self.streams.open.get_mut(&stream_id)
            && stream.phase == StreamPhase::Reserved
        {
            stream.phase = StreamPhase::Open;
            self.streams.active[Side::Server] += 1;
            if self.enforce_concurrency(Side::Server, stream_id, Some(&block_evidence), context)? {
                return Ok(());
            }
        }
        let mut failure = malformed.then_some(Status::Malformed);
        let meta = match validate(role, &headers) {
            Ok(meta) => meta,
            Err(detail) => {
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::HeaderSemantics,
                        detail,
                    )
                    .stream(Some(stream_id))
                    .evidence(block.clone(), block_sources.clone()),
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
        if side == Side::Server
            && role == FieldRole::Response
            && client_initiated
            && self.control.goaway[Side::Server].is_some_and(|last| stream_id > last)
        {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::ResponseAfterGoaway,
                    RESPONSE_AFTER_GOAWAY,
                )
                .stream(Some(stream_id))
                .evidence(block.clone(), block_sources.clone()),
            )?;
            failure = Some(Status::Malformed);
        }
        if role == FieldRole::Trailer
            && self
                .streams
                .open
                .get(&stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| matches!(msg.status_code, Some(204 | 304)))
        {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::HeaderSemantics,
                    "204 and 304 responses cannot contain trailers",
                )
                .stream(Some(stream_id))
                .evidence(block.clone(), block_sources.clone()),
            )?;
            failure = Some(Status::Malformed);
        }
        if role == FieldRole::Trailer && !end_stream {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::TrailerWithoutEndStream,
                    "a trailer block must terminate the stream",
                )
                .stream(Some(stream_id))
                .evidence(block.clone(), block_sources.clone()),
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if let Some(status) = meta.status
            && (100..200).contains(&status)
            && end_stream
        {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Malformed,
                    IssueCode::InformationalEndStream,
                    "a 1xx response must not end the stream",
                )
                .stream(Some(stream_id))
                .evidence(block.clone(), block_sources.clone()),
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if meta.protocol {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Stream,
                    Status::Unsupported,
                    IssueCode::ExtendedConnect,
                    ":protocol extended CONNECT is outside this analyzer's semantics",
                )
                .stream(Some(stream_id))
                .evidence(block.clone(), block_sources.clone()),
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
                && let Some(stream) = self.streams.open.get_mut(&stream_id)
                && let Some(msg) = stream.msgs[side].as_mut()
            {
                msg.failure = Some(status);
            }
        } else {
            let trailer_conflict = self
                .streams
                .open
                .get(&stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| msg.trailers_seen);
            if trailer_conflict {
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::SecondTrailerBlock,
                        "a third header block follows completed trailers",
                    )
                    .stream(Some(stream_id))
                    .evidence(block.clone(), block_sources.clone()),
                )?;
            }
            if trailer_conflict {
                failure = Some(Status::Malformed);
            }
            let flawed = failure.is_some();
            let stream = self
                .streams
                .open
                .get_mut(&stream_id)
                .ok_or(Error::Invariant("stream"))?;
            if let Some(msg) = stream.msgs[side].as_mut() {
                if flawed {
                    msg.failure = Some(Status::Malformed);
                }
                msg.trailers_seen = true;
                let added = headers
                    .iter()
                    .map(|h| h.name.len() + h.value.len() + budget::HEADER_OVERHEAD)
                    .sum::<usize>()
                    + block.len();
                let stream = self
                    .streams
                    .open
                    .get_mut(&stream_id)
                    .ok_or(Error::Invariant("stream"))?;
                match stream.msgs[side].as_mut() {
                    Some(msg) => {
                        context.charge(&mut msg.charge, added)?;
                        msg.trailers.extend(headers);
                        msg.header_blocks.push(block);
                        if let Some(sources) = block_sources {
                            context.track(&mut msg.charge, &sources)?;
                            msg.sets.push(sources);
                        }
                        if let Some(set) = compression {
                            context.track(&mut msg.charge, &set)?;
                            msg.compression.push(set);
                        }
                    }
                    None => context.charge(&mut self.charge, added)?,
                }
            } else {
                failure = Some(Status::Malformed);
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Stream,
                        Status::Malformed,
                        IssueCode::HeadersAfterEnd,
                        "HEADERS arrived after the sender already ended the stream",
                    )
                    .stream(Some(stream_id))
                    .evidence(block, block_sources),
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
        self.issue(context, Fault::new(self.dir_flow(Side::Server), IssueScope::Stream, if invalid { Status::Malformed } else { Status::Incomplete }, if early.ended { IssueCode::HeadersAfterEnd } else if invalid { IssueCode::HeaderSemantics } else { IssueCode::EarlyResponseTrailers }, "HEADERS follow a previously observed final response whose opener was capture-delayed").stream(Some(id)).certainty(if invalid { Certainty::Confirmed } else { Certainty::Indeterminate }).evidence(evidence.wire.clone(), evidence.sources.clone()))?;
        if self.streams.open.contains_key(&id) {
            // The provisional response has no message builder to emit. Its
            // error must not terminate the independently captured request.
            self.end_side(
                Side::Server,
                id,
                if invalid {
                    Status::Malformed
                } else {
                    Status::Incomplete
                },
                context,
            )?;
        } else if let Some(state) = self.streams.early_responses.get_mut(&id) {
            state.ended = true;
        }
        Ok(true)
    }
}
