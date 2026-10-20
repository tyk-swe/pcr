// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod headers;
mod messages;
mod push;

use super::super::Error;
use super::super::model::{Certainty, IssueScope, Status};
use super::super::stream::{CLIENT, Phase as StreamPhase, SERVER, StreamState, peer};
use super::{ConnectionState, Context, Evidence, Fault, Phase, resources};
use bytes::Bytes;

impl ConnectionState {
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
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if !self.pending_openers.contains_key(&id) {
            self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
            self.pending_openers.insert(id, code);
        }
        Ok(())
    }

    fn resolve_pending_opener(&mut self, id: u32, context: &mut Context<'_>) {
        if self.pending_openers.remove(&id).is_some() {
            self.release_conn(context, resources::CLOSED_STREAM_OVERHEAD);
        }
    }

    pub(crate) fn reconcile_pending_openers(
        &mut self,
        owner: usize,
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
        owner: usize,
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
        owner: usize,
        below: Option<u32>,
        detail: &'static str,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let mut fault = None;
        for (&id, &code) in &self.pending_openers {
            context.check_deadline()?;
            if id.is_multiple_of(2) == (owner == SERVER) && below.is_none_or(|bound| id < bound) {
                fault = Some((id, code));
                break;
            }
        }
        if let Some((id, code)) = fault {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(peer(owner)),
                    http2_stream_id: Some(id),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code,
                    detail: detail.into(),
                    wire: Bytes::new(),
                    sources: None,
                },
            )?;
            self.fail(context, Status::Malformed)?;
        }
        Ok(())
    }

    pub(crate) fn begin_stream(
        &mut self,
        side: usize,
        stream_id: u32,
        evidence: Option<&Evidence>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let initiator = if stream_id.is_multiple_of(2) {
            SERVER
        } else {
            CLIENT
        };
        if side != initiator {
            let flow = self.dir_flow(side);
            self.issue(
                context,
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
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if initiator == CLIENT && stream_id <= self.max_initiated[CLIENT] {
            let flow = self.dir_flow(side);
            self.issue(
                context,
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
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if initiator == CLIENT {
            self.max_initiated[CLIENT] = stream_id;
            // Only a connection observed from its start proves lower ids were
            // never opened; a mid-capture start may have missed their openers.
            if self.clean_start {
                self.reconcile_pending_openers_below(CLIENT, stream_id, context)?;
                if matches!(self.phase, Phase::Dead) {
                    return Ok(());
                }
            }
        }
        let open_count = self
            .streams
            .values()
            .filter(|stream| stream.phase != StreamPhase::Closed)
            .count();
        if open_count + 1 > context.limits.max_active_streams
            || self.active[initiator] + 1 > context.limits.max_active_streams
        {
            let flow = self.dir_flow(side);
            self.issue(
                context,
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
            self.fail(context, Status::Limit)?;
            return Ok(());
        }
        self.resolve_pending_opener(stream_id, context);
        let early_response = self.early_response_headers.remove(&stream_id);
        if early_response.is_some() {
            self.release_conn(context, resources::CLOSED_STREAM_OVERHEAD);
        } else {
            context.check_streams()?;
            self.admitted_streams += 1;
        }
        self.charge_conn(context, resources::STREAM_OVERHEAD)?;
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
        self.enforce_concurrency(initiator, stream_id, evidence, context)?;
        Ok(())
    }

    fn enforce_concurrency(
        &mut self,
        initiator: usize,
        stream_id: u32,
        evidence: Option<&Evidence>,
        context: &mut Context<'_>,
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
            context,
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
            self.close_stream(stream_id, Status::Malformed, None, context)?;
        }
        Ok(confirmed)
    }

    pub(crate) fn stream_window_overflows(
        &self,
        side: usize,
        stream_id: u32,
        context: &Context<'_>,
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
            context.check_deadline()?;
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
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if self.stream_window_overflows(side, stream_id, context)? {
            self.issue(context, Fault {
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
            self.close_stream(stream_id, Status::Malformed, None, context)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn end_side(
        &mut self,
        side: usize,
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
                context,
            )?;
            if emitted == Status::Malformed {
                return self.close_stream(stream_id, Status::Malformed, None, context);
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
                self.retain_closed_credit(stream_id, context)?;
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
                    context,
                    resources::STREAM_OVERHEAD - resources::CLOSED_STREAM_OVERHEAD,
                );
            }
        }
        Ok(())
    }

    // A peer's terminal event may precede the captured opener. Preserve its
    // direction without discarding the opener's independently valid evidence.
    pub(crate) fn reject_priority_stream(
        &mut self,
        side: usize,
        id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.streams.contains_key(&id) {
            return self.close_stream(id, Status::Malformed, None, context);
        }
        let owner = if id.is_multiple_of(2) { SERVER } else { CLIENT };
        if self.closed.contains_key(&id) || id <= self.max_initiated[owner] {
            return Ok(());
        }
        if side == SERVER && owner == CLIENT {
            self.retain_early_parent(id, context)?;
            self.early_response_headers
                .get_mut(&id)
                .expect("early parent")
                .ended = true;
        } else {
            context.check_streams()?;
            self.admitted_streams += 1;
            self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
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

    pub(crate) fn reset_stream(
        &mut self,
        side: usize,
        stream_id: u32,
        evidence: Evidence,
        context: &mut Context<'_>,
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
                context,
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
                self.fail(context, Status::Malformed)?;
            } else if side == SERVER && owner == CLIENT {
                self.retain_pending_opener(stream_id, "reset_idle_stream", context)?;
                self.retain_early_parent(stream_id, context)?;
                self.early_response_headers
                    .get_mut(&stream_id)
                    .expect("early parent")
                    .ended = true;
            } else {
                self.retain_pending_opener(stream_id, "reset_idle_stream", context)?;
                context.check_streams()?;
                self.admitted_streams += 1;
                self.charge_conn(context, resources::CLOSED_STREAM_OVERHEAD)?;
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
        self.close_stream(stream_id, Status::Reset, Some(side), context)
    }

    pub(crate) fn close_stream(
        &mut self,
        stream_id: u32,
        status: Status,
        reset_by: Option<usize>,
        context: &mut Context<'_>,
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
                self.emit_message(msg_side, msg, status, context)?;
            }
        }
        let request = self.streams.get(&stream_id).and_then(|s| s.request);
        self.retain_closed_credit(stream_id, context)?;
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
            context,
            resources::STREAM_OVERHEAD - resources::CLOSED_STREAM_OVERHEAD,
        );
        Ok(())
    }
}
