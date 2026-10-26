// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod headers;
mod messages;
mod push;

use super::super::Error;
use super::super::model::{Certainty, IssueScope, Status};
use super::super::stream::{Phase as StreamPhase, StreamState};
use super::{ConnectionState, Context, Evidence, Fault, Phase};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::{PerSide, Side};
use bytes::Bytes;

impl ConnectionState {
    pub(crate) fn opener_exhausted(&self, owner: Side) -> bool {
        self.clean_start
            && self
                .directions
                .get(owner)
                .is_some_and(|dir| dir.fully_consumed_fin)
    }

    pub(crate) fn retain_pending_opener(
        &mut self,
        id: u32,
        code: IssueCode,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !self.streams.pending_openers.contains_key(&id) {
            context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
            self.streams.pending_openers.insert(id, code);
        }
        Ok(())
    }

    fn resolve_pending_opener(&mut self, id: u32, context: &mut Context<'_>) -> Result<(), Error> {
        if self.streams.pending_openers.remove(&id).is_some() {
            context.release(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
        }
        Ok(())
    }

    pub(crate) fn reconcile_pending_openers(
        &mut self,
        owner: Side,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.confirm_pending_openers(
            owner,
            None,
            "clean initiator FIN proves no opener exists; original frame evidence is retained in the earlier issue",
            context,
        )
    }

    /// A later stream id from the initiator proves that every lower same-parity
    /// id it never opened will stay idle: initiators use ids in increasing order.
    pub(crate) fn reconcile_pending_openers_below(
        &mut self,
        owner: Side,
        bound: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.confirm_pending_openers(
            owner,
            Some(bound),
            "a later stream id from the initiator proves no opener exists; original frame evidence is retained in the earlier issue",
            context,
        )
    }

    fn confirm_pending_openers(
        &mut self,
        owner: Side,
        below: Option<u32>,
        detail: &'static str,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let mut fault = None;
        for (&id, &code) in &self.streams.pending_openers {
            context.check_deadline()?;
            if Side::initiator_of(id) == owner && below.is_none_or(|bound| id < bound) {
                fault = Some((id, code));
                break;
            }
        }
        if let Some((id, code)) = fault {
            self.reject(
                context,
                Fault::new(
                    self.dir_flow(owner.peer()),
                    IssueScope::Connection,
                    Status::Malformed,
                    code,
                    detail,
                )
                .stream(Some(id)),
            )?;
        }
        Ok(())
    }

    pub(crate) fn begin_stream(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: Option<&Evidence>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let initiator = Side::initiator_of(stream_id);
        if initiator == Side::Client {
            self.streams.max_initiated[Side::Client] = stream_id;
            // Only a connection observed from its start proves lower ids were
            // never opened; a mid-capture start may have missed their openers.
            if self.clean_start {
                self.reconcile_pending_openers_below(Side::Client, stream_id, context)?;
                if matches!(self.phase, Phase::Dead) {
                    return Ok(());
                }
            }
        }
        let open_count = self
            .streams
            .open
            .values()
            .filter(|stream| stream.phase != StreamPhase::Closed)
            .count();
        if open_count + 1 > context.limits.max_active_streams
            || self.streams.active[initiator] + 1 > context.limits.max_active_streams
        {
            let flow = self.dir_flow(side);
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Limit,
                    IssueCode::ActiveStreams,
                    "concurrent streams exceed the configured bound",
                )
                .stream(Some(stream_id))
                .evidence(
                    evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                    evidence.and_then(|e| e.sources.clone()),
                ),
            )?;
            return Ok(());
        }
        self.resolve_pending_opener(stream_id, context)?;
        let early_response = self.streams.early_responses.remove(&stream_id);
        if early_response.is_some() {
            context.release(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
        } else {
            context.check_streams()?;
            self.streams.admitted += 1;
        }
        context.charge(&mut self.charge, budget::STREAM_OVERHEAD)?;
        let windows = PerSide::new(
            i64::from(
                self.control.settings[Side::Server]
                    .acknowledged
                    .initial_window_size,
            ),
            i64::from(
                self.control.settings[Side::Client]
                    .acknowledged
                    .initial_window_size,
            ),
        );
        let mut state = StreamState::open(initiator, windows);
        state.early_response = early_response;
        state.ended[Side::Server] = early_response.is_some_and(|early| early.ended);
        state.unprocessed =
            self.control.goaway[initiator.peer()].is_some_and(|last| stream_id > last);
        self.streams.open.insert(stream_id, state);
        self.streams.active[initiator] += 1;
        self.enforce_concurrency(initiator, stream_id, evidence, context)?;
        Ok(())
    }

    fn enforce_concurrency(
        &mut self,
        initiator: Side,
        stream_id: u32,
        evidence: Option<&Evidence>,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let receiver = &self.control.settings[initiator.peer()];
        let Some(max) = receiver.acknowledged.max_concurrent_streams else {
            return Ok(false);
        };
        if self.streams.active[initiator] <= max as usize {
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
                    .is_some_and(|dir| dir.closed && dir.buffer.is_empty() && dir.chain.is_none()));
        self.issue(
            context,
            Fault::new(
                self.dir_flow(initiator),
                IssueScope::Stream,
                Status::Malformed,
                IssueCode::ConcurrentStreams,
                "open streams exceed the peer's acknowledged limit",
            )
            .stream(Some(stream_id))
            .certainty(if confirmed {
                Certainty::Confirmed
            } else {
                Certainty::ObservedOrder
            })
            .evidence(
                evidence.map_or_else(Bytes::new, |e| e.wire.clone()),
                evidence.and_then(|e| e.sources.clone()),
            ),
        )?;
        if confirmed {
            self.close_stream(stream_id, Status::Malformed, None, context)?;
        }
        Ok(confirmed)
    }

    pub(crate) fn stream_window_overflows(
        &self,
        side: Side,
        stream_id: u32,
        context: &Context<'_>,
    ) -> Result<bool, Error> {
        let Some(stream) = self.streams.open.get(&stream_id) else {
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
        for pending in &self.control.settings[side.peer()].pending {
            context.check_deadline()?;
            let before = pending.window_grants.get(&stream_id).copied().unwrap_or(0);
            if before > previous_grants {
                overflow |= base.saturating_add(before).saturating_add(delta.min(0))
                    > super::super::settings::WINDOW_MAX;
            }
            previous_grants = before;
            delta = delta.saturating_add(pending.window_delta);
        }
        if granted > previous_grants || self.control.settings[side.peer()].pending.is_empty() {
            overflow |= stream.send_window[side].saturating_add(delta.min(0))
                > super::super::settings::WINDOW_MAX;
        }
        Ok(overflow)
    }

    pub(crate) fn confirm_stream_window_overflow(
        &mut self,
        side: Side,
        stream_id: u32,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if self.stream_window_overflows(side, stream_id, context)? {
            self.issue(context, Fault::new(self.dir_flow(side), IssueScope::Stream, Status::Malformed, IssueCode::StreamWindowOverflow, "stream flow window remains above 2^31-1 after the sender ended; earlier WINDOW_UPDATE evidence is retained").stream(Some(stream_id)))?;
            self.close_stream(stream_id, Status::Malformed, None, context)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn end_side(
        &mut self,
        side: Side,
        stream_id: u32,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if status == Status::Complete
            && self.confirm_stream_window_overflow(side, stream_id, context)?
        {
            return Ok(());
        }
        let defer_complete = status == Status::Complete
            && (self.waiting_settings_ack(Side::Client) || self.waiting_settings_ack(Side::Server));
        let Some(stream) = self.streams.open.get_mut(&stream_id) else {
            return Ok(());
        };
        stream.ended[side] = true;
        if side == Side::Server
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
                context,
            )?;
            if emitted == Status::Malformed {
                return self.close_stream(stream_id, Status::Malformed, None, context);
            }
        }
        let stream = self
            .streams
            .open
            .get_mut(&stream_id)
            .ok_or(Error::Invariant("stream"))?;
        if stream.ended.all(|ended| *ended) {
            if stream.phase == StreamPhase::Open {
                let owner = stream.initiator;
                self.streams.active[owner] = self.streams.active[owner].saturating_sub(1);
            }
            stream.phase = StreamPhase::Closed;
            if stream.msgs.iter().all(Option::is_none) {
                let request = stream.request;
                self.retain_closed_credit(stream_id, context)?;
                self.streams.open.remove(&stream_id);
                self.streams.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        ended: PerSide::new(true, true),
                        reset_by: None,
                        request,
                    },
                );
                context.release(
                    &mut self.charge,
                    budget::STREAM_OVERHEAD - budget::CLOSED_STREAM_OVERHEAD,
                )?;
            }
        }
        Ok(())
    }

    // A peer's terminal event may precede the captured opener. Preserve its
    // direction without discarding the opener's independently valid evidence.
    pub(crate) fn reject_priority_stream(
        &mut self,
        side: Side,
        id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.streams.open.contains_key(&id) {
            return self.close_stream(id, Status::Malformed, None, context);
        }
        let owner = Side::initiator_of(id);
        if self.streams.closed.contains_key(&id) || id <= self.streams.max_initiated[owner] {
            return Ok(());
        }
        if side == Side::Server && owner == Side::Client {
            self.retain_early_parent(id, context)?;
            self.streams
                .early_responses
                .get_mut(&id)
                .ok_or(Error::Invariant("early parent"))?
                .ended = true;
        } else {
            context.check_streams()?;
            self.streams.admitted += 1;
            context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
            self.streams.closed.insert(
                id,
                super::ClosedStream {
                    ended: PerSide::new(true, true),
                    reset_by: None,
                    request: None,
                },
            );
        }
        Ok(())
    }

    pub(crate) fn reset_stream(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !self.streams.open.contains_key(&stream_id) {
            let owner = Side::initiator_of(stream_id);
            if self.streams.closed.contains_key(&stream_id)
                || stream_id <= self.streams.max_initiated[owner]
            {
                return Ok(());
            }
            let confirmed = self.clean_start && (side == owner || self.opener_exhausted(owner));
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Connection,
                    if confirmed {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    IssueCode::ResetIdleStream,
                    "RST_STREAM on a stream that was never opened",
                )
                .stream(Some(stream_id))
                .certainty(if confirmed {
                    Certainty::Confirmed
                } else {
                    Certainty::Indeterminate
                })
                .evidence(evidence.wire, evidence.sources),
            )?;
            if confirmed {
                self.fail(context, Status::Malformed)?;
            } else if side == Side::Server && owner == Side::Client {
                self.retain_pending_opener(stream_id, IssueCode::ResetIdleStream, context)?;
                self.retain_early_parent(stream_id, context)?;
                self.streams
                    .early_responses
                    .get_mut(&stream_id)
                    .ok_or(Error::Invariant("early parent"))?
                    .ended = true;
            } else {
                self.retain_pending_opener(stream_id, IssueCode::ResetIdleStream, context)?;
                context.check_streams()?;
                self.streams.admitted += 1;
                context.charge(&mut self.charge, budget::CLOSED_STREAM_OVERHEAD)?;
                self.streams.closed.insert(
                    stream_id,
                    super::ClosedStream {
                        ended: PerSide::new(side == Side::Client, side == Side::Server),
                        reset_by: Some(side),
                        request: None,
                    },
                );
            }
            return Ok(());
        }
        self.close_stream(stream_id, Status::Reset, Some(side), context)
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: u32,
        status: Status,
        reset_by: Option<Side>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let stream = self
            .streams
            .open
            .get_mut(&stream_id)
            .ok_or(Error::Invariant("stream"))?;
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
        let was_open = stream.phase == StreamPhase::Open;
        stream.phase = StreamPhase::Closed;
        stream.ended = PerSide::new(true, true);
        if was_open {
            let owner = stream.initiator;
            self.streams.active[owner] = self.streams.active[owner].saturating_sub(1);
        }
        for msg_side in Side::BOTH {
            if let Some(msg) = self
                .streams
                .open
                .get_mut(&stream_id)
                .and_then(|s| s.msgs[msg_side].take())
            {
                self.emit_message(msg_side, msg, status, context)?;
            }
        }
        let request = self.streams.open.get(&stream_id).and_then(|s| s.request);
        self.retain_closed_credit(stream_id, context)?;
        self.streams.open.remove(&stream_id);
        self.streams.closed.insert(
            stream_id,
            super::ClosedStream {
                ended,
                reset_by,
                request,
            },
        );
        context.release(
            &mut self.charge,
            budget::STREAM_OVERHEAD - budget::CLOSED_STREAM_OVERHEAD,
        )?;
        Ok(())
    }
}
