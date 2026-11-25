// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stream admission, concurrency enforcement, window overflow confirmation, and closing.

mod headers;
mod messages;
mod push;

use super::super::Error;
use super::super::model::{Certainty, Status};
use super::super::settings::WINDOW_MAX;
use super::super::stream::{ClosedStream, Phase as StreamPhase, StreamState};
use super::{
    ActiveState, Context, ElectedDirection, Evidence, Fault, Reporter, StepAbort, StepResult,
};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::{PerSide, Side};

impl ActiveState {
    pub(crate) fn opener_exhausted(&self, owner: Side) -> bool {
        self.clean_start
            && self
                .directions
                .get(owner)
                .is_some_and(|dir| dir.fully_consumed_fin)
    }

    pub(crate) fn reconcile_pending_openers(
        &self,
        owner: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        self.confirm_pending_openers(
            owner,
            None,
            "clean initiator FIN proves no opener exists; original frame evidence is retained in the earlier issue",
            reporter,
            context,
        )
    }

    /// A later stream id from the initiator proves that every lower same-parity
    /// id it never opened will stay idle: initiators use ids in increasing order.
    pub(crate) fn reconcile_pending_openers_below(
        &self,
        owner: Side,
        bound: u32,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        self.confirm_pending_openers(
            owner,
            Some(bound),
            "a later stream id from the initiator proves no opener exists; original frame evidence is retained in the earlier issue",
            reporter,
            context,
        )
    }

    fn confirm_pending_openers(
        &self,
        owner: Side,
        below: Option<u32>,
        detail: &'static str,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if let Some((id, code)) = self.streams.first_pending_opener(owner, below, context)? {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(owner.peer()),
                    Status::Malformed,
                    code,
                    detail,
                )
                .with_stream(Some(id)),
            );
        }
        Ok(())
    }

    pub(crate) fn begin_stream(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: Option<&Evidence>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let initiator = Side::initiator_of(stream_id);
        if initiator == Side::Client {
            self.streams.set_max_initiated(Side::Client, stream_id);
            // Only a connection observed from its start proves lower ids were
            // never opened; a mid-capture start may have missed their openers.
            if self.clean_start {
                self.reconcile_pending_openers_below(Side::Client, stream_id, reporter, context)?;
            }
        }
        if self.streams.non_closed_count() + 1 > context.limits.max_active_streams
            || self.streams.active_count(initiator) + 1 > context.limits.max_active_streams
        {
            let mut fault = Fault::connection(
                self.directions.flow(side),
                Status::Limit,
                IssueCode::ActiveStreams,
                "concurrent streams exceed the configured bound",
            )
            .with_stream(Some(stream_id));
            if let Some(evidence) = evidence {
                fault = fault.with_evidence_ref(evidence);
            }
            return reporter.reject(context, fault);
        }
        self.streams.resolve_pending_opener(stream_id, context)?;
        let early_response = self.streams.take_early_response(stream_id, context)?;
        let windows = self.control.initial_windows();
        let mut state = StreamState::open(initiator, windows);
        state.early_response = early_response;
        state.ended[Side::Server] = early_response.is_some_and(|early| early.ended);
        state.unprocessed =
            self.control.goaway[initiator.peer()].is_some_and(|last| stream_id > last);
        self.streams
            .admit_open(stream_id, state, early_response.is_some(), context)?;
        self.enforce_concurrency(initiator, stream_id, evidence, reporter, context)?;
        Ok(())
    }

    pub(super) fn enforce_concurrency(
        &mut self,
        initiator: Side,
        stream_id: u32,
        evidence: Option<&Evidence>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let receiver = &self.control.settings[initiator.peer()];
        let Some(max) = receiver.acknowledged.max_concurrent_streams else {
            return Ok(false);
        };
        if self.streams.active_count(initiator) <= max as usize {
            return Ok(false);
        }
        // Any existing stream might already have been reset by the peer in
        // the other capture direction. Only a zero limit proves rejection
        // without needing to infer whether prior streams remain open. A fully
        // consumed receiving FIN also rules out any hidden peer resets.
        let confirmed = receiver.pending.is_empty()
            && (max == 0
                || self
                    .directions
                    .get(initiator.peer())
                    .is_some_and(ElectedDirection::is_clean_eof));
        let mut fault = Fault::stream(
            self.directions.flow(initiator),
            stream_id,
            Status::Malformed,
            IssueCode::ConcurrentStreams,
            "open streams exceed the peer's acknowledged limit",
        )
        .with_certainty(if confirmed {
            Certainty::Confirmed
        } else {
            Certainty::ObservedOrder
        });
        if let Some(evidence) = evidence {
            fault = fault.with_evidence_ref(evidence);
        }
        reporter.issue(context, fault)?;
        if confirmed {
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        }
        Ok(confirmed)
    }

    pub(crate) fn stream_window_overflows(
        &self,
        side: Side,
        stream_id: u32,
        context: &Context<'_>,
    ) -> Result<bool, Error> {
        let Some(stream) = self.streams.open_get(stream_id) else {
            return Ok(false);
        };
        let granted = stream.window_granted[side];
        let base = stream.send_window[side].saturating_sub(granted);
        let mut previous_grants = 0;
        let mut delta = 0i64;
        let mut overflow = base > WINDOW_MAX;
        // A WINDOW_UPDATE is received after every preceding SETTINGS in the
        // granting direction. Later decreases cannot repair an earlier overflow.
        // Unacknowledged increases cannot establish receipt; only a nonpositive
        // cumulative delta lowers the bound. ACKed increases are already in base.
        // Subtracting all observed DATA makes each intermediate bound conservative.
        for pending in &self.control.settings[side.peer()].pending {
            context.check_deadline()?;
            let before = pending.window_grants.get(&stream_id).copied().unwrap_or(0);
            if before > previous_grants {
                overflow |= base.saturating_add(before).saturating_add(delta.min(0)) > WINDOW_MAX;
            }
            previous_grants = before;
            delta = delta.saturating_add(pending.window_delta);
        }
        if granted > previous_grants || self.control.settings[side.peer()].pending.is_empty() {
            overflow |= stream.send_window[side].saturating_add(delta.min(0)) > WINDOW_MAX;
        }
        Ok(overflow)
    }

    pub(crate) fn confirm_stream_window_overflow(
        &mut self,
        side: Side,
        stream_id: u32,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        if !self.stream_window_overflows(side, stream_id, context)? {
            return Ok(false);
        }
        reporter.issue(
            context,
            Fault::stream(
                self.directions.flow(side),
                stream_id,
                Status::Malformed,
                IssueCode::StreamWindowOverflow,
                "stream flow window remains above 2^31-1 after the sender ended; earlier WINDOW_UPDATE evidence is retained",
            ),
        )?;
        self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        Ok(true)
    }

    pub(crate) fn end_side(
        &mut self,
        side: Side,
        stream_id: u32,
        status: Status,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if status == Status::Complete
            && self.confirm_stream_window_overflow(side, stream_id, reporter, context)?
        {
            return Ok(());
        }
        let defer_complete = status == Status::Complete && self.waiting_any_settings_ack();
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return Ok(());
        };
        stream.ended[side] = true;
        if side == Side::Server
            && let Some(early) = stream.early_response.as_mut()
        {
            early.ended = true;
        }
        let unprocessed = stream.unprocessed;
        let msg = if defer_complete {
            None
        } else {
            stream.msgs[side].take()
        };
        if let Some(msg) = msg {
            let emit_status = if unprocessed {
                Status::Unprocessed
            } else {
                status
            };
            let emitted = self.emit_message_with_completion(
                side,
                msg,
                emit_status,
                status == Status::Complete,
                reporter,
                context,
            )?;
            if emitted == Status::Malformed {
                return self.close_stream(stream_id, Status::Malformed, None, reporter, context);
            }
        }
        let Some(stream) = self.streams.open_get(stream_id) else {
            return Ok(());
        };
        if !stream.ended.all(|ended| *ended) {
            return Ok(());
        }
        let ready_to_retire = stream.msgs.iter().all(Option::is_none);
        let request = stream.request;
        self.streams.mark_open_closed_phase(stream_id);
        if ready_to_retire {
            self.streams.move_open_to_closed(
                stream_id,
                ClosedStream {
                    ended: PerSide::new(true, true),
                    reset_by: None,
                    request,
                },
                context,
            )?;
        }
        Ok(())
    }

    // A peer's terminal event may precede the captured opener. Preserve its
    // direction without discarding the opener's independently valid evidence.
    pub(crate) fn reject_priority_stream(
        &mut self,
        side: Side,
        id: u32,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.streams.is_open(id) {
            return self.close_stream(id, Status::Malformed, None, reporter, context);
        }
        if self.streams.is_closed_or_implicit(id) {
            return Ok(());
        }
        if side == Side::Server && Side::initiator_of(id) == Side::Client {
            self.streams.ensure_early_response(id, context)?.ended = true;
        } else {
            self.streams.admit_closed(
                id,
                ClosedStream {
                    ended: PerSide::new(true, true),
                    reset_by: None,
                    request: None,
                },
                context,
            )?;
        }
        Ok(())
    }

    pub(crate) fn reset_stream(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.streams.is_open(stream_id) {
            return self.close_stream(stream_id, Status::Reset, Some(side), reporter, context);
        }
        if self.streams.is_closed_or_implicit(stream_id) {
            return Ok(());
        }
        let owner = Side::initiator_of(stream_id);
        let confirmed = self.clean_start && (side == owner || self.opener_exhausted(owner));
        let (status, certainty) = if confirmed {
            (Status::Malformed, Certainty::Confirmed)
        } else {
            (Status::Incomplete, Certainty::Indeterminate)
        };
        reporter.issue(
            context,
            Fault::connection(
                self.directions.flow(side),
                status,
                IssueCode::ResetIdleStream,
                "RST_STREAM on a stream that was never opened",
            )
            .with_stream(Some(stream_id))
            .with_certainty(certainty)
            .with_evidence(evidence.wire, evidence.sources),
        )?;
        if confirmed {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        self.streams
            .retain_pending_opener(stream_id, IssueCode::ResetIdleStream, context)?;
        if side == Side::Server && owner == Side::Client {
            self.streams
                .ensure_early_response(stream_id, context)?
                .ended = true;
        } else {
            self.streams.admit_closed(
                stream_id,
                ClosedStream {
                    ended: PerSide::new(side == Side::Client, side == Side::Server),
                    reset_by: Some(side),
                    request: None,
                },
                context,
            )?;
        }
        Ok(())
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: u32,
        status: Status,
        reset_by: Option<Side>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return Ok(());
        };
        if stream.phase == StreamPhase::Closed
            && stream.ended.all(|ended| *ended)
            && stream.msgs.iter().all(Option::is_none)
        {
            return Ok(());
        }
        let mut ended = stream.ended;
        if let Some(side) = reset_by {
            ended[side] = true;
        } else {
            ended = PerSide::new(true, true);
        }
        stream.ended = PerSide::new(true, true);
        let client_msg = stream.msgs[Side::Client].take();
        let server_msg = stream.msgs[Side::Server].take();
        let request = stream.request;
        self.streams.mark_open_closed_phase(stream_id);
        for (msg_side, msg) in [(Side::Client, client_msg), (Side::Server, server_msg)] {
            if let Some(msg) = msg {
                self.emit_message(msg_side, msg, status, reporter, context)?;
            }
        }
        self.streams.move_open_to_closed(
            stream_id,
            ClosedStream {
                ended,
                reset_by,
                request,
            },
            context,
        )?;
        Ok(())
    }
}
