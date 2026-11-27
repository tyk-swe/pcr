// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DATA payload validation, stream flow control, and message body retention.

use super::super::{ActiveState, Context, Evidence, Fault, Reporter, StepAbort, StepResult};
use crate::analysis::http2::model::{Certainty, IssueScope, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::Phase as StreamPhase;
use crate::analysis::http2::{Error, IssueCode};

pub(super) struct DataHead {
    pub(super) side: Side,
    pub(super) stream_id: u32,
    pub(super) length: u32,
    pub(super) data_bytes: u64,
    pub(super) end_stream: bool,
}

impl ActiveState {
    pub(super) fn data_frame(
        &mut self,
        head: DataHead,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.apply_connection_data_window(
            head.side,
            head.stream_id,
            head.length,
            &evidence,
            reporter,
            context,
        )? {
            return Ok(());
        }
        // In-flight peer DATA after a reset still consumes connection credit,
        // but cannot establish a stream error from cross-direction ordering.
        if self
            .streams
            .is_peer_reset_in_flight(head.side, head.stream_id)
        {
            return Ok(());
        }
        if !self.streams.is_open(head.stream_id) {
            return self.handle_non_open_stream_data(head, evidence, reporter, context);
        }
        if self.check_open_stream_rejects_data(
            head.side,
            head.stream_id,
            &evidence,
            reporter,
            context,
        )? {
            return Ok(());
        }
        if self.apply_stream_data_window(
            head.side,
            head.stream_id,
            head.length,
            &evidence,
            reporter,
            context,
        )? {
            return Ok(());
        }
        self.record_open_stream_data(head, evidence, reporter, context)
    }

    fn apply_connection_data_window(
        &mut self,
        side: Side,
        stream_id: u32,
        length: u32,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        self.control.send_window[side] = self.control.send_window[side]
            .checked_sub(i64::from(length))
            .ok_or(Error::Application(
                crate::analysis::application::Error::Limit {
                    field: "flow_window",
                    limit: 0x8000_0000,
                },
            ))?;
        let window = self.control.send_window[side];
        if window < -(1i64 << 31) {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::ConnectionWindowUnderflow,
                    "connection flow window passed the 31-bit floor",
                )
                .with_stream(Some(stream_id))
                .with_evidence_ref(evidence),
            );
        }
        if length > 0 && window < 0 {
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::ConnectionWindowExceeded,
                    "DATA exceeded the observed connection window",
                )
                .with_stream(Some(stream_id))
                .with_certainty(Certainty::ObservedOrder)
                .with_evidence_ref(evidence),
            )?;
        }
        Ok(window < 0 && self.reconcile_closed_credit(side, Some(stream_id), reporter, context)?)
    }

    fn handle_non_open_stream_data(
        &mut self,
        head: DataHead,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let DataHead {
            side,
            stream_id,
            data_bytes,
            end_stream,
            ..
        } = head;
        let owner = Side::initiator_of(stream_id);
        let closed = self.streams.is_closed_or_implicit(stream_id);
        if !closed && self.clean_start && side == Side::Server && owner == Side::Client {
            let early = self.streams.early_response(stream_id).copied();
            if early.is_none_or(|state| !state.final_seen || state.ended) {
                reporter.issue(
                    context,
                    Fault::stream(
                        self.directions.flow(side),
                        stream_id,
                        Status::Malformed,
                        IssueCode::DataWithoutHeaders,
                        "server DATA preceded any response HEADERS in the same ordered byte stream",
                    )
                    .with_evidence(evidence.wire, evidence.sources),
                )?;
                self.streams
                    .ensure_early_response(stream_id, context)?
                    .ended = true;
                return Ok(());
            }
            // A capture-early final response that cannot carry content is
            // contradicted by content in the server's own ordered bytes.
            if data_bytes > 0
                && let Some(early) = self.streams.early_response_mut(stream_id)
                && early.final_seen
                && early.bodyless
                && !early.ended
            {
                early.ended = true;
                reporter.issue(
                    context,
                    Fault::stream(
                        self.directions.flow(side),
                        stream_id,
                        Status::Malformed,
                        IssueCode::BodylessResponseBody,
                        "a capture-delayed response that must not carry content carried DATA",
                    )
                    .with_evidence(evidence.wire, evidence.sources),
                )?;
                return Ok(());
            }
        }
        let uncertain = !closed && (!self.clean_start || side != owner);
        if side == Side::Server
            && end_stream
            && let Some(early) = self.streams.early_response_mut(stream_id)
        {
            early.ended = true;
        }
        let (scope, code, detail) = if closed {
            (
                IssueScope::Stream,
                IssueCode::DataClosedStream,
                "DATA arrived on a fully closed stream",
            )
        } else {
            (
                IssueScope::Connection,
                IssueCode::DataUnknownStream,
                "DATA arrived on a stream that was never opened",
            )
        };
        let (status, certainty) = if uncertain {
            (Status::Incomplete, Certainty::Indeterminate)
        } else {
            (Status::Malformed, Certainty::Confirmed)
        };
        reporter.issue(
            context,
            Fault::new(self.directions.flow(side), scope, status, code, detail)
                .with_stream(Some(stream_id))
                .with_certainty(certainty)
                .with_evidence(evidence.wire, evidence.sources),
        )?;
        if !closed && !uncertain {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        Ok(())
    }

    fn check_open_stream_rejects_data(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let Some(stream) = self.streams.open_get(stream_id) else {
            return Ok(true);
        };
        if stream.phase == StreamPhase::Open && !stream.ended[side] {
            return Ok(false);
        }
        let reserved = stream.phase == StreamPhase::Reserved;
        let preserve_delayed_request = side == Side::Server && stream.early_response.is_some();
        let scope = if reserved {
            IssueScope::Connection
        } else {
            IssueScope::Stream
        };
        reporter.issue(
            context,
            Fault::new(
                self.directions.flow(side),
                scope,
                Status::Malformed,
                IssueCode::DataClosedStream,
                "DATA arrived on a stream closed to the sender",
            )
            .with_stream(Some(stream_id))
            .with_evidence_ref(evidence),
        )?;
        if reserved {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        if !preserve_delayed_request {
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        }
        Ok(true)
    }

    fn apply_stream_data_window(
        &mut self,
        side: Side,
        stream_id: u32,
        length: u32,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return Ok(true);
        };
        stream.send_window[side] -= i64::from(length);
        let window = stream.send_window[side];
        if length > 0 {
            stream.credit_exceeded[side] = window < 0;
        }
        if window < -(1i64 << 31) {
            reporter.issue(
                context,
                Fault::stream(
                    self.directions.flow(side),
                    stream_id,
                    Status::Malformed,
                    IssueCode::StreamWindowUnderflow,
                    "stream flow window passed the 31-bit floor",
                )
                .with_evidence_ref(evidence),
            )?;
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
            return Ok(true);
        }
        if length > 0 && window < 0 {
            reporter.issue(
                context,
                Fault::stream(
                    self.directions.flow(side),
                    stream_id,
                    Status::Malformed,
                    IssueCode::StreamWindowExceeded,
                    "DATA exceeded the observed stream window",
                )
                .with_certainty(Certainty::ObservedOrder)
                .with_evidence_ref(evidence),
            )?;
        }
        self.reconcile_closed_credit(side, Some(stream_id), reporter, context)
    }

    fn record_open_stream_data(
        &mut self,
        head: DataHead,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let DataHead {
            side,
            stream_id,
            data_bytes,
            end_stream,
            ..
        } = head;
        let flow = self.directions.flow(side);
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return Ok(());
        };
        let trace_content = side == Side::Client && stream.method.as_deref() == Some(b"TRACE");
        if data_bytes > 0 && (trace_content || (stream.response_bodyless && side == Side::Server)) {
            let code = if trace_content {
                IssueCode::TraceRequestBody
            } else {
                IssueCode::BodylessResponseBody
            };
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    code,
                    "a message that must not carry content carried DATA",
                )
                .with_evidence_ref(&evidence),
            )?;
            if let Some(msg) = stream.msgs[side].as_mut() {
                msg.failure = Some(Status::Malformed);
            }
        }
        let Some(msg) = stream.msgs[side].as_mut() else {
            if side == Side::Server && stream.early_response.is_some_and(|early| early.final_seen) {
                reporter.issue(
                    context,
                    Fault::stream(
                        flow,
                        stream_id,
                        Status::Incomplete,
                        IssueCode::DataAfterEarlyResponse,
                        "DATA follows response HEADERS observed before the delayed client opener",
                    )
                    .with_certainty(Certainty::Indeterminate)
                    .with_evidence(evidence.wire, evidence.sources),
                )?;
                if end_stream {
                    self.end_side(side, stream_id, Status::Complete, reporter, context)?;
                }
                return Ok(());
            }
            reporter.issue(
                context,
                Fault::stream(
                    flow,
                    stream_id,
                    Status::Malformed,
                    IssueCode::DataWithoutHeaders,
                    "DATA arrived before a header block on the stream",
                )
                .with_evidence(evidence.wire, evidence.sources),
            )?;
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
            return Ok(());
        };
        if msg.trailers_seen {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    IssueCode::DataAfterTrailers,
                    "DATA arrived after a trailer block",
                )
                .with_evidence_ref(&evidence),
            )?;
            msg.failure = Some(Status::Malformed);
        }
        msg.saw_body = true;
        msg.body_bytes = msg.body_bytes.saturating_add(data_bytes);
        if msg.body_bytes > context.limits.max_body_bytes {
            return reporter.reject(
                context,
                Fault::stream(
                    flow,
                    stream_id,
                    Status::Limit,
                    IssueCode::BodyLimit,
                    "observed message body exceeds the configured bound",
                )
                .with_evidence(evidence.wire, evidence.sources),
            );
        }
        if let Some(sources) = evidence.sources {
            context.track(&mut msg.charge, &sources)?;
            msg.sets.push(sources);
        }
        let malformed = msg.failure == Some(Status::Malformed);
        if malformed {
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        } else if end_stream {
            self.end_side(side, stream_id, Status::Complete, reporter, context)?;
        }
        Ok(())
    }
}
