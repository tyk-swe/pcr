// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Push-promise validation, stream reservation, and parent reconciliation.

use super::super::{ActiveState, Context, Evidence, Fault, Reporter, StepAbort, StepResult};
use crate::analysis::http2::headers::{FieldRole, Meta, validate};
use crate::analysis::http2::model::{Certainty, Header, MessageKind, Status};
use crate::analysis::http2::side::{PerSide, Side};
use crate::analysis::http2::stream::{
    ClosedStream, Decoded, HeaderSection, Phase as StreamPhase, StreamState,
};
use crate::analysis::http2::{Error, IssueCode};
use bytes::Bytes;

struct PushEnvelope {
    promised_reset_in_flight: bool,
    delayed_parent: bool,
}

struct PromisedStream {
    side: Side,
    parent_id: u32,
    promised: u32,
    index: u64,
    method: Option<Bytes>,
    promised_reset_in_flight: bool,
    rejected: bool,
}

fn validate_pushed_request(headers: &[Header]) -> Result<Meta, &'static str> {
    let meta = validate(FieldRole::Request, headers)?;
    if !matches!(meta.method.as_deref(), Some(b"GET" | b"HEAD")) {
        return Err("a pushed request must use a known safe and cacheable method");
    }
    if meta.content_length.is_some_and(|length| length != 0) {
        return Err("a pushed request must not indicate request content");
    }
    Ok(meta)
}

impl ActiveState {
    pub(crate) fn push_promise(
        &mut self,
        side: Side,
        stream_id: u32,
        promised: u32,
        decoded: Decoded,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let evidence = Evidence::new(decoded.block.clone(), decoded.sources.clone());
        let envelope =
            self.validate_push_envelope(side, stream_id, promised, &evidence, reporter, context)?;
        // A rejected promise never opens the promised stream, so provisional
        // idle-stream evidence for that id is only released once it is admitted.
        self.streams.resolve_pending_opener(promised, context)?;
        let meta = validate_pushed_request(&decoded.headers);
        let mut msg = Self::new_message(promised, MessageKind::PushPromise, context)?;
        let sources = decoded.sources.clone();
        msg.retain_headers(HeaderSection::Initial, decoded, context)?;
        msg.promised_by = Some(stream_id);
        msg.request = self.streams.request_index(stream_id);

        let rejected = meta.is_err();
        let mut promised_method = None;
        match meta {
            Ok(meta) => {
                msg.content_length = meta.content_length;
                promised_method = meta.method;
            }
            Err(detail) => {
                msg.failure = Some(Status::Malformed);
                reporter.issue(
                    context,
                    Fault::stream(
                        self.directions.flow(side),
                        promised,
                        Status::Malformed,
                        IssueCode::PushPromiseHeaders,
                        detail,
                    )
                    .with_evidence(Bytes::new(), sources),
                )?;
            }
        }
        let index = msg.index;
        if envelope.delayed_parent && !rejected {
            self.streams.ensure_early_response(stream_id, context)?;
            self.deferred.push_promise(msg, context)?;
        } else {
            self.emit_message(Side::Server, msg, Status::Complete, reporter, context)?;
        }
        self.admit_promised_stream(
            PromisedStream {
                side,
                parent_id: stream_id,
                promised,
                index,
                method: promised_method,
                promised_reset_in_flight: envelope.promised_reset_in_flight,
                rejected,
            },
            reporter,
            context,
        )
    }

    fn validate_push_envelope(
        &mut self,
        side: Side,
        stream_id: u32,
        promised: u32,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<PushEnvelope> {
        let flow = self.directions.flow(side);
        if side == Side::Client {
            return reporter.reject(
                context,
                Fault::connection(
                    flow,
                    Status::Malformed,
                    IssueCode::ClientPushPromise,
                    "a client sent PUSH_PROMISE",
                )
                .with_stream(Some(stream_id))
                .with_evidence_ref(evidence),
            );
        }
        if !self.control.settings[Side::Client].acknowledged.enable_push {
            let certainty = if self.control.settings[Side::Client].pending.is_empty() {
                Certainty::Confirmed
            } else {
                Certainty::ObservedOrder
            };
            reporter.issue(
                context,
                Fault::connection(
                    flow.clone(),
                    Status::Malformed,
                    IssueCode::PushDisabled,
                    "PUSH_PROMISE while the client has push disabled",
                )
                .with_stream(Some(stream_id))
                .with_certainty(certainty)
                .with_evidence_ref(evidence),
            )?;
            if certainty == Certainty::Confirmed {
                return Err(StepAbort::ConnectionFailed(Status::Malformed));
            }
        }
        let promised_reset_in_flight = self.streams.is_peer_reset_in_flight(Side::Server, promised);
        let valid_promised_id = Side::initiator_of(promised) == Side::Server
            && promised > self.streams.max_initiated(Side::Server)
            && (!self.streams.is_closed_record(promised) || promised_reset_in_flight);
        if !valid_promised_id {
            return reporter.reject(
                context,
                Fault::connection(
                    flow,
                    Status::Malformed,
                    IssueCode::PromisedStreamId,
                    "PUSH_PROMISE names a reused or client-numbered stream",
                )
                .with_stream(Some(stream_id))
                .with_evidence_ref(evidence),
            );
        }
        self.streams.set_max_initiated(Side::Server, promised);

        let parent_open = self.streams.open_get(stream_id).is_some_and(|stream| {
            stream.phase == StreamPhase::Open
                && stream.initiator == Side::Client
                && !stream.ended[Side::Server]
        });
        // A peer promise may have been sent before it received our reset.
        // RFC 9113 §5.1 still requires HPACK processing and stream reservation.
        let in_flight_after_reset = self.streams.is_peer_reset_in_flight(side, stream_id);
        let delayed_parent = !self.opener_exhausted(Side::Client)
            && Side::initiator_of(stream_id) == Side::Client
            && stream_id > self.streams.max_initiated(Side::Client)
            && !self.streams.is_open(stream_id)
            && !self.streams.is_closed_record(stream_id)
            && !self
                .streams
                .early_response(stream_id)
                .is_some_and(|early| early.ended);
        if !parent_open && !in_flight_after_reset && !delayed_parent {
            return reporter.reject(
                context,
                Fault::connection(
                    flow,
                    Status::Malformed,
                    IssueCode::PushPromiseClosedParent,
                    "PUSH_PROMISE on a parent stream that cannot push",
                )
                .with_stream(Some(stream_id))
                .with_evidence_ref(evidence),
            );
        }
        Ok(PushEnvelope {
            promised_reset_in_flight,
            delayed_parent,
        })
    }

    fn admit_promised_stream(
        &mut self,
        stream: PromisedStream,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let PromisedStream {
            side,
            parent_id,
            promised,
            index,
            method,
            promised_reset_in_flight,
            rejected,
        } = stream;
        if promised_reset_in_flight {
            // The promise can precede receipt of a peer reset, but must not
            // revive the reset stream or emit later in-flight response messages.
            return Ok(());
        }
        if rejected {
            self.streams.admit_closed(
                promised,
                ClosedStream {
                    ended: PerSide::new(true, true),
                    reset_by: None,
                    request: Some(index),
                },
                context,
            )?;
            return Ok(());
        }
        if self.streams.non_closed_count() + 1 > context.limits.max_active_streams {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Limit,
                    IssueCode::ActiveStreams,
                    "concurrent streams exceed the configured bound",
                )
                .with_stream(Some(promised)),
            );
        }
        let windows = self.control.initial_windows();
        let mut promised_stream = StreamState::reserved(parent_id, windows);
        promised_stream.request = Some(index);
        promised_stream.method = method;
        promised_stream.unprocessed =
            self.control.goaway[Side::Client].is_some_and(|last| promised > last);
        self.streams
            .admit_reserved(promised, promised_stream, context)?;
        Ok(())
    }

    pub(super) fn release_parent_promises(
        &mut self,
        parent_id: u32,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let request = self
            .streams
            .open_get(parent_id)
            .and_then(|stream| stream.request);
        for mut msg in self.deferred.take_parent_promises(parent_id, context)? {
            msg.request = request;
            self.emit_message(Side::Server, msg, Status::Complete, reporter, context)?;
        }
        Ok(())
    }
}
