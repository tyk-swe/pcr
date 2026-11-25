// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! WINDOW_UPDATE handling and reconciliation of closed-stream credit.

use super::super::super::model::{Certainty, Status};
use super::super::super::settings;
use super::super::super::stream::Phase as StreamPhase;
use super::super::{
    ActiveState, Context, ElectedDirection, Evidence, Fault, Reporter, StepAbort, StepResult,
};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::Side;

impl ActiveState {
    pub(crate) fn window_update(
        &mut self,
        side: Side,
        stream_id: u32,
        increment: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if stream_id == 0 {
            self.connection_window_update(side, increment, evidence, reporter, context)
        } else {
            self.stream_window_update(side, stream_id, increment, evidence, reporter, context)
        }
    }

    fn connection_window_update(
        &mut self,
        side: Side,
        increment: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let grant = side.peer();
        self.control.send_window[grant] =
            self.control.send_window[grant].saturating_add(i64::from(increment));
        if self.control.send_window[grant] <= settings::WINDOW_MAX {
            return Ok(());
        }
        let confirmed = self
            .directions
            .get(grant)
            .is_some_and(|dir| dir.closed && dir.buffer.is_empty());
        let (status, certainty) = if confirmed {
            (Status::Malformed, Certainty::Confirmed)
        } else {
            (Status::Incomplete, Certainty::ObservedOrder)
        };
        reporter.issue(
            context,
            Fault::connection(
                self.directions.flow(side),
                status,
                IssueCode::ConnectionWindowOverflow,
                "connection flow window exceeds 2^31-1",
            )
            .with_stream(Some(0))
            .with_certainty(certainty)
            .with_evidence(evidence.wire, evidence.sources),
        )?;
        if confirmed {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        Ok(())
    }

    fn stream_window_update(
        &mut self,
        side: Side,
        stream_id: u32,
        increment: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let grant = side.peer();
        self.streams
            .credit_closed_stream(stream_id, grant, increment, context)?;
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return self
                .handle_unopen_stream_window_update(side, stream_id, evidence, reporter, context);
        };
        if stream.phase == StreamPhase::Closed {
            return Ok(());
        }
        stream.window_granted[grant] =
            stream.window_granted[grant].saturating_add(i64::from(increment));
        stream.send_window[grant] = stream.send_window[grant].saturating_add(i64::from(increment));
        if stream.send_window[grant] >= 0 {
            stream.credit_exceeded[grant] = false;
        }
        let overflowed = stream.send_window[grant] > settings::WINDOW_MAX;
        let sender_ended = stream.ended[grant];
        if !overflowed {
            return Ok(());
        }
        let confirmed = sender_ended && self.stream_window_overflows(grant, stream_id, context)?;
        let (status, certainty) = if confirmed {
            (Status::Malformed, Certainty::Confirmed)
        } else {
            (Status::Incomplete, Certainty::ObservedOrder)
        };
        reporter.issue(
            context,
            Fault::stream(
                self.directions.flow(side),
                stream_id,
                status,
                IssueCode::StreamWindowOverflow,
                "stream flow window exceeds 2^31-1",
            )
            .with_certainty(certainty)
            .with_evidence(evidence.wire, evidence.sources),
        )?;
        if confirmed {
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
        }
        Ok(())
    }

    fn handle_unopen_stream_window_update(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.streams.is_closed_or_implicit(stream_id) {
            return Ok(());
        }
        let owner = Side::initiator_of(stream_id);
        let confirmed_idle = self.clean_start && (side == owner || self.opener_exhausted(owner));
        reporter.issue(
            context,
            Fault::connection(
                self.directions.flow(side),
                Status::Malformed,
                IssueCode::WindowUpdateUnknownStream,
                "WINDOW_UPDATE on a stream that is not open",
            )
            .with_stream(Some(stream_id))
            .with_certainty(if confirmed_idle {
                Certainty::Confirmed
            } else {
                Certainty::ObservedOrder
            })
            .with_evidence(evidence.wire, evidence.sources),
        )?;
        if confirmed_idle {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        self.streams.retain_pending_opener(
            stream_id,
            IssueCode::WindowUpdateUnknownStream,
            context,
        )?;
        Ok(())
    }

    /// A clean, fully consumed granting direction cannot hide later credit.
    pub(crate) fn reconcile_closed_credit(
        &mut self,
        side: Side,
        only_stream: Option<u32>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        if !self.is_h2()
            || !self.clean_start
            || !self
                .directions
                .get(side.peer())
                .is_some_and(ElectedDirection::is_clean_eof)
        {
            return Ok(false);
        }
        if self.control.send_window[side] < 0 {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::ConnectionWindowExceeded,
                    "DATA exhausted connection credit after the granting direction ended; prior DATA evidence is retained",
                )
                .with_stream(Some(0)),
            );
        }
        // A not-yet-ACKed SETTINGS increase may already have supplied credit.
        let mut delta = 0i64;
        let mut extra = 0i64;
        for pending in &self.control.settings[side.peer()].pending {
            context.check_deadline()?;
            delta += pending.window_delta;
            extra = extra.max(delta);
        }
        if self.reconcile_open_stream_credit(side, only_stream, extra, reporter, context)? {
            return Ok(true);
        }
        self.reconcile_closed_stream_debt(side, only_stream, extra, reporter, context)?;
        Ok(false)
    }

    fn reconcile_open_stream_credit(
        &mut self,
        side: Side,
        only_stream: Option<u32>,
        extra: i64,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let flow = self.directions.flow(side);
        let mut cursor = 0;
        loop {
            context.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self.streams.next_open_after(cursor),
            };
            let Some(id) = id else {
                return Ok(false);
            };
            cursor = id;
            let Some(stream) = self.streams.open_mut(id) else {
                continue;
            };
            if !(stream.credit_exceeded[side] && stream.send_window[side] + extra < 0) {
                continue;
            }
            stream.credit_exceeded[side] = false;
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    id,
                    Status::Malformed,
                    IssueCode::StreamWindowExceeded,
                    "DATA exhausted stream credit after the granting direction ended; prior DATA evidence is retained",
                ),
            )?;
            self.close_stream(id, Status::Malformed, None, reporter, context)?;
            if only_stream.is_some() {
                return Ok(true);
            }
        }
    }

    fn reconcile_closed_stream_debt(
        &mut self,
        side: Side,
        only_stream: Option<u32>,
        extra: i64,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), crate::analysis::http2::Error> {
        let flow = self.directions.flow(side);
        let mut cursor = 0;
        loop {
            context.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self.streams.next_closed_credit_after(cursor),
            };
            let Some(id) = id else {
                return Ok(());
            };
            cursor = id;
            if !self
                .streams
                .closed_credit_debt(id, side)
                .is_some_and(|window| window + extra < 0)
            {
                continue;
            }
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    id,
                    Status::Malformed,
                    IssueCode::StreamWindowExceeded,
                    "completed stream DATA exhausted credit before the granting direction ended; earlier DATA evidence is retained",
                ),
            )?;
            self.streams.clear_closed_credit_side(id, side, context)?;
        }
    }
}
