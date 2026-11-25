// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection shutdown: TCP close, EOF reconciliation, termination, and dead transition.

mod teardown;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, PeerSettings, Status};
use super::{
    ActiveState, ConnectionState, Context, DeadState, DirectionPhase, Fault, PendingCounts, Phase,
    Reporter, SniffingDirections, SniffingState, StepAbort, StepResult, UpgradeEvidence,
};
use crate::analysis::ScopedFlowKey;
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::Side;
use bytes::Bytes;

impl ActiveState {
    fn close_step(
        &mut self,
        flow: &ScopedFlowKey,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if !self.directions.has_flow(flow) && self.directions.has_flow(&flow.reverse()) {
            let phase = if self.is_h2() {
                DirectionPhase::Frames
            } else {
                DirectionPhase::Prelude
            };
            self.directions.ensure_server(
                flow.clone(),
                phase,
                true,
                &self.control.settings[Side::Client],
                context,
            )?;
        }
        let Some(side) = self.directions.side_of(flow) else {
            return Ok(());
        };
        if let Some(dir) = self.directions.get_mut(side) {
            dir.closed = true;
        }
        if self.is_h2() {
            self.pump(reporter, context)?;
        }
        self.reconcile_direction_eof(side, flow, reporter, context)?;
        if side == Side::Server {
            self.report_unmatched_response_at_eof(reporter, context)?;
        }
        self.drain_truncated_direction(side, reporter, context)?;
        self.flush_side_open_messages(side, reporter, context)?;
        self.maybe_mark_done(reporter, context)?;
        Ok(())
    }

    fn reconcile_direction_eof(
        &mut self,
        side: Side,
        flow: &ScopedFlowKey,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.is_h2()
            && let Some(dir) = self.directions.get_mut(side)
            && dir.is_clean_eof()
            && dir.phase == DirectionPhase::Frames
        {
            dir.fully_consumed_fin = true;
            if self.clean_start {
                self.reconcile_pending_openers(side, reporter, context)?;
            }
        }
        if self.is_h2()
            && self.control.send_window[side] > super::super::settings::WINDOW_MAX
            && self
                .directions
                .get(side)
                .is_some_and(|dir| dir.buffer.is_empty())
        {
            return reporter.reject(
                context,
                Fault::connection(
                    flow.clone(),
                    Status::Malformed,
                    IssueCode::ConnectionWindowOverflow,
                    "connection flow window remains above 2^31-1 after sender FIN; earlier WINDOW_UPDATE evidence is retained",
                )
                .with_stream(Some(0)),
            );
        }
        self.reconcile_closed_credit(side.peer(), None, reporter, context)?;
        if !self.is_h2()
            || !self
                .directions
                .get(side)
                .is_some_and(|dir| dir.buffer.is_empty() && dir.chain.is_none())
        {
            return Ok(());
        }
        if side == Side::Client
            && self.clean_start
            && let Some(parent) = self
                .deferred
                .promises
                .front()
                .and_then(|msg| msg.promised_by)
        {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(Side::Server),
                    Status::Malformed,
                    IssueCode::PushPromiseClosedParent,
                    "client FIN proves the pending promise has no parent opener; promise evidence is retained in its message",
                )
                .with_stream(Some(parent)),
            );
        }
        // Check before truncation handling discards any undecoded bytes.
        // A clean sender FIN excludes future DATA that could lower credit.
        let mut cursor = 0;
        while let Some(id) = self.streams.next_open_after(cursor) {
            context.check_deadline()?;
            cursor = id;
            self.confirm_stream_window_overflow(side, id, reporter, context)?;
        }
        Ok(())
    }

    fn drain_truncated_direction(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let deferred_ack = self.waiting_settings_ack(side);
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(());
        };
        dir.closed = true;
        let partial = dir.buffer.len();
        if partial > 0 && !deferred_ack {
            let (wire, sets) = dir.buffer.take(partial, context)?;
            let sources = union_balanced(sets)?;
            let detail = match dir.phase {
                DirectionPhase::Prelude => "connection closed mid HTTP/1 exchange",
                DirectionPhase::Preface => "connection closed inside the client preface",
                DirectionPhase::Frames => "connection closed mid-frame",
            };
            reporter.issue(
                context,
                Fault::capture(
                    dir.flow.clone(),
                    Status::Incomplete,
                    IssueCode::TruncatedStream,
                    detail,
                )
                .with_evidence(wire, sources),
            )?;
        }
        if let Some(mut chain) = dir.chain.take() {
            context.release_all(&mut chain.charge)?;
            reporter.issue(
                context,
                Fault::capture(
                    dir.flow.clone(),
                    Status::Incomplete,
                    IssueCode::TruncatedHeaderBlock,
                    "connection closed inside a header block",
                )
                .with_stream(Some(chain.stream_id))
                .with_evidence(
                    Bytes::copy_from_slice(&chain.bytes),
                    union_balanced(chain.sets)?,
                ),
            )?;
        }
        Ok(())
    }

    fn flush_side_open_messages(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let ids: Vec<u32> = self
            .streams
            .open_iter()
            .filter(|(_, stream)| stream.msgs[side].is_some() && !stream.ended[side])
            .map(|(id, _)| id)
            .collect();
        let flushed = !ids.is_empty();
        for id in ids {
            self.end_side(side, id, Status::Incomplete, reporter, context)?;
        }
        if flushed {
            reporter.worst(Status::Incomplete);
        }
        Ok(())
    }

    fn maybe_mark_done(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let both_closed = Side::BOTH
            .into_iter()
            .all(|side| self.directions.get(side).is_some_and(|dir| dir.closed));
        if !both_closed || self.streams.has_open_messages() {
            return Ok(());
        }
        self.done = true;
        if self.streams.has_unfinished_open_streams() {
            reporter.worst(Status::Incomplete);
        }
        self.directions.release_live(context)
    }

    pub(super) fn collect_unobserved_settings(&self) -> Vec<(ScopedFlowKey, Certainty)> {
        if self.settings_audited {
            return Vec::new();
        }
        let certainty = if self.clean_start {
            Certainty::Confirmed
        } else {
            Certainty::Indeterminate
        };
        let mut unobserved = Vec::new();
        for side in Side::BOTH {
            if let Some(dir) = self.directions.get(side)
                && !self.control.settings[side].seen
                && (self.clean_start || dir.saw_frame)
            {
                unobserved.push((dir.flow.clone(), certainty));
            }
        }
        unobserved
    }

    pub(super) fn into_dead(
        mut self,
        status: Option<Status>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<DeadState, Error> {
        if let Some(status) = status {
            for dir in self.directions.iter_mut() {
                if let Some(mut chain) = dir.chain.take() {
                    context.release_all(&mut chain.charge)?;
                    reporter.issue(
                        context,
                        Fault::capture(
                            dir.flow.clone(),
                            status,
                            IssueCode::TruncatedHeaderBlock,
                            "the connection failed inside a header block",
                        )
                        .with_stream(Some(chain.stream_id))
                        .with_evidence(
                            Bytes::copy_from_slice(&chain.bytes),
                            union_balanced(chain.sets)?,
                        ),
                    )?;
                }
            }
            self.flush_messages(status, reporter, context)?;
        }
        let unobserved_settings = self.collect_unobserved_settings();
        let flow = self.directions.primary_flow();
        let known_flows = self.directions.known_flows();
        let client_settings = self.control.settings[Side::Client].advertised;
        let server_settings = self.control.settings[Side::Server].advertised;
        let client_window = self.control.send_window[Side::Client];
        let server_window = self.control.send_window[Side::Server];
        let streams_admitted = self.streams.admitted();

        self.directions.release_live(context)?;
        self.deferred.release_all(context)?;
        if let Some(prelude) = self.prelude.take() {
            prelude.release_all(context)?;
        }
        let pending = self.control.release_all(context)?;
        self.streams.release_all(context)?;

        Ok(DeadState {
            flow,
            known_flows,
            client_settings,
            server_settings,
            client_window,
            server_window,
            streams_admitted,
            pending,
            upgrade: self.upgrade,
            overhead: self.directions.overhead,
            unobserved_settings,
        })
    }
}

impl ConnectionState {
    pub(crate) fn close(
        &mut self,
        flow: &ScopedFlowKey,
        reset: bool,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::Dead(_)) {
            return Ok(());
        }
        if reset {
            return self.terminate(
                flow,
                Status::Reset,
                IssueCode::ConnectionReset,
                "the TCP connection reset",
                context,
            );
        }
        match &mut self.phase {
            Phase::Dead(_) => Ok(()),
            Phase::Sniffing(sniff) => {
                if !sniff.directions.has_flow(flow) && sniff.directions.has_flow(&flow.reverse()) {
                    sniff
                        .directions
                        .ensure_candidate(flow.clone(), true, context)?;
                }
                if let Some(dir) = sniff.directions.find_mut(flow) {
                    dir.closed = true;
                    let partial = dir.buffer.len();
                    if partial > 0 {
                        let (wire, sets) = dir.buffer.take(partial, context)?;
                        let sources = union_balanced(sets)?;
                        self.reporter.issue(
                            context,
                            Fault::capture(
                                dir.flow.clone(),
                                Status::Incomplete,
                                IssueCode::TruncatedStream,
                                "connection closed before startup was determined",
                            )
                            .with_evidence(wire, sources),
                        )?;
                    }
                }
                Ok(())
            }
            Phase::Active(active) => match active.close_step(flow, &mut self.reporter, context) {
                Ok(()) => Ok(()),
                Err(StepAbort::ConnectionFailed(status)) => self.fail_to_dead(status, context),
                Err(StepAbort::Fatal(error)) => Err(error),
            },
        }
    }

    pub(crate) fn terminate(
        &mut self,
        flow: &ScopedFlowKey,
        status: Status,
        code: IssueCode,
        detail: &'static str,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::Dead(_)) {
            return Ok(());
        }
        if code == IssueCode::TcpEvicted
            && matches!(&self.phase, Phase::Active(active) if active.done)
        {
            return Ok(());
        }
        self.reporter
            .issue(context, Fault::capture(flow.clone(), status, code, detail))?;
        match &mut self.phase {
            Phase::Dead(_) => return Ok(()),
            Phase::Sniffing(sniff) => {
                for dir in &mut sniff.directions.candidates {
                    let partial = dir.buffer.len();
                    if partial > 0 {
                        let (wire, sets) = dir.buffer.take(partial, context)?;
                        let sources = union_balanced(sets)?;
                        self.reporter.issue(
                            context,
                            Fault::capture(
                                dir.flow.clone(),
                                status,
                                IssueCode::UnconsumedBytes,
                                "the byte stream ended with undecoded bytes",
                            )
                            .with_evidence(wire, sources),
                        )?;
                    }
                }
            }
            Phase::Active(active) => {
                active.clean_start = false;
                active.report_unmatched_response_at_eof(&mut self.reporter, context)?;
                for dir in active.directions.iter_mut() {
                    let partial = dir.buffer.len();
                    if partial > 0 {
                        let (wire, sets) = dir.buffer.take(partial, context)?;
                        let sources = union_balanced(sets)?;
                        self.reporter.issue(
                            context,
                            Fault::capture(
                                dir.flow.clone(),
                                status,
                                IssueCode::UnconsumedBytes,
                                "the byte stream ended with undecoded bytes",
                            )
                            .with_evidence(wire, sources),
                        )?;
                    }
                    if let Some(mut chain) = dir.chain.take() {
                        context.release_all(&mut chain.charge)?;
                        let sources = union_balanced(std::mem::take(&mut chain.sets))?;
                        self.reporter.issue(
                            context,
                            Fault::capture(
                                dir.flow.clone(),
                                status,
                                IssueCode::TruncatedHeaderBlock,
                                "the byte stream ended inside a header block",
                            )
                            .with_stream(Some(chain.stream_id))
                            .with_evidence(Bytes::copy_from_slice(&chain.bytes), sources),
                        )?;
                    }
                }
            }
        }
        self.fail_to_dead(status, context)
    }

    pub(crate) fn fail_to_dead(
        &mut self,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::Dead(_)) {
            return Ok(());
        }
        self.reporter.worst(status);
        let placeholder = Phase::Sniffing(SniffingState {
            directions: SniffingDirections::new(),
        });
        let dead = match std::mem::replace(&mut self.phase, placeholder) {
            Phase::Dead(dead) => dead,
            Phase::Sniffing(mut sniff) => {
                let flow = sniff.directions.primary_flow(&self.reporter.first_flow);
                let known_flows = sniff.directions.known_flows();
                sniff.directions.release_buffers(context)?;
                Box::new(DeadState {
                    flow,
                    known_flows,
                    client_settings: PeerSettings::default(),
                    server_settings: PeerSettings::default(),
                    client_window: 65_535,
                    server_window: 65_535,
                    streams_admitted: 0,
                    pending: PendingCounts::default(),
                    upgrade: UpgradeEvidence::default(),
                    overhead: sniff.directions.overhead,
                    unobserved_settings: Vec::new(),
                })
            }
            Phase::Active(active) => {
                Box::new(active.into_dead(Some(status), &mut self.reporter, context)?)
            }
        };
        self.phase = Phase::Dead(dead);
        Ok(())
    }
}
