// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Push-promise validation, stream reservation, and parent reconciliation.

use super::super::{ConnectionState, Context, Decoded, Fault, resources};
use crate::analysis::http2::Error;
use crate::analysis::http2::headers::{FieldRole, validate};
use crate::analysis::http2::model::{Certainty, IssueScope, MessageKind, Status};
use crate::analysis::http2::side::{PerSide, Side};
use crate::analysis::http2::stream::{Phase as StreamPhase, StreamState};
use bytes::Bytes;

impl ConnectionState {
    pub(crate) fn push_promise(
        &mut self,
        side: Side,
        stream_id: u32,
        promised: u32,
        decoded: Decoded,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Decoded {
            headers,
            block,
            sources: block_sources,
            compression,
        } = decoded;
        if side == Side::Client {
            self.issue(
                context,
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
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if !self.settings[Side::Client].acknowledged.enable_push {
            let certainty = if self.settings[Side::Client].pending.is_empty() {
                Certainty::Confirmed
            } else {
                Certainty::ObservedOrder
            };
            self.issue(
                context,
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
                self.fail(context, Status::Malformed)?;
                return Ok(());
            }
        }
        let promised_reset_in_flight = self.closed.get(&promised).is_some_and(|closed| {
            closed.reset_by == Some(Side::Client) && !closed.ended[Side::Server]
        });
        if Side::initiator_of(promised) == Side::Server
            && promised > self.max_initiated[Side::Server]
            && (!self.closed.contains_key(&promised) || promised_reset_in_flight)
        {
            self.max_initiated[Side::Server] = promised;
        } else {
            self.issue(
                context,
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
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        let parent_open = self.streams.get(&stream_id).is_some_and(|s| {
            s.phase == StreamPhase::Open && s.initiator == Side::Client && !s.ended[Side::Server]
        });
        // A peer promise may have been sent before it received our reset.
        // RFC 9113 §5.1 still requires HPACK processing and stream reservation.
        let in_flight_after_reset = self
            .closed
            .get(&stream_id)
            .is_some_and(|closed| closed.reset_by == Some(side.peer()) && !closed.ended[side]);
        let delayed_parent = !self.opener_exhausted(Side::Client)
            && Side::initiator_of(stream_id) == Side::Client
            && stream_id > self.max_initiated[Side::Client]
            && !self.streams.contains_key(&stream_id)
            && !self.closed.contains_key(&stream_id)
            && !self
                .early_response_headers
                .get(&stream_id)
                .is_some_and(|early| early.ended);
        if !parent_open && !in_flight_after_reset && !delayed_parent {
            self.issue(
                context,
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
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        // A rejected promise never opens the promised stream, so provisional
        // idle-stream evidence for that id is only released once it is admitted.
        self.resolve_pending_opener(promised, context)?;
        let meta = validate(FieldRole::Request, &headers).and_then(|meta| {
            if !matches!(meta.method.as_deref(), Some(b"GET" | b"HEAD")) {
                return Err("a pushed request must use a known safe and cacheable method");
            }
            if meta.content_length.is_some_and(|length| length != 0) {
                return Err("a pushed request must not indicate request content");
            }
            Ok(meta)
        });
        let mut msg = self.new_message(promised, MessageKind::PushPromise, context)?;
        let content_charge = headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + resources::HEADER_OVERHEAD)
            .sum::<usize>()
            + block.len();
        self.charge_conn(context, content_charge)?;
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
            self.charge_conn(context, charge)?;
            context.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.sets.push(sources);
        }
        if let Some(set) = compression {
            let frames = set.frames().len();
            let charge = resources::SET_OVERHEAD + frames * resources::SPAN_OVERHEAD;
            self.charge_conn(context, charge)?;
            context.charge_spans(frames)?;
            msg.charged += charge;
            msg.charged_spans += frames;
            msg.compression.push(set);
        }
        let rejected = meta.is_err();
        let mut promised_method = None;
        if let Err(detail) = meta {
            msg.failure = Some(Status::Malformed);
            self.issue(
                context,
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
            self.retain_early_parent(stream_id, context)?;
            self.charge_conn(context, resources::PENDING_OVERHEAD)?;
            self.parent_deferred.push_back(msg);
        } else {
            self.emit_message(Side::Server, msg, Status::Complete, context)?;
        }
        if promised_reset_in_flight {
            // The promise can precede receipt of a peer reset, but must not
            // revive the reset stream or emit later in-flight response messages.
            return Ok(());
        }
        if rejected {
            context.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
            self.closed.insert(
                promised,
                super::super::ClosedStream {
                    ended: PerSide::new(true, true),
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
        if open_count + 1 > context.limits.max_active_streams {
            self.issue(
                context,
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
            self.fail(context, Status::Limit)?;
            return Ok(());
        }
        context.check_streams()?;
        self.admitted_streams += 1;
        self.charge_conn(context, resources::STREAM_OVERHEAD)?;
        let windows = PerSide::new(
            i64::from(self.settings[Side::Server].acknowledged.initial_window_size),
            i64::from(self.settings[Side::Client].acknowledged.initial_window_size),
        );
        let mut promised_stream = StreamState::reserved(stream_id, windows);
        promised_stream.request = Some(index);
        promised_stream.method = promised_method;
        promised_stream.unprocessed = self.goaway[Side::Client].is_some_and(|last| promised > last);
        self.streams.insert(promised, promised_stream);
        Ok(())
    }

    pub(super) fn retain_early_parent(
        &mut self,
        id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !self.early_response_headers.contains_key(&id) {
            context.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
            self.early_response_headers.insert(id, Default::default());
        }
        Ok(())
    }

    pub(super) fn release_parent_promises(
        &mut self,
        id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let count = self.parent_deferred.len();
        let request = self.streams.get(&id).and_then(|stream| stream.request);
        for _ in 0..count {
            context.check_deadline()?;
            let mut msg = self
                .parent_deferred
                .pop_front()
                .ok_or(Error::Invariant("pending promise"))?;
            if msg.promised_by == Some(id) {
                self.release_conn(context, resources::PENDING_OVERHEAD)?;
                msg.request = request;
                self.emit_message(Side::Server, msg, Status::Complete, context)?;
            } else {
                self.parent_deferred.push_back(msg);
            }
        }
        Ok(())
    }
}
