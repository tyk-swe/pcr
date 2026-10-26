// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection shutdown: draining, closing, termination, and failure.

mod teardown;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{IssueScope, Status};
use super::{ConnectionState, Context, DirectionPhase, Fault, Phase};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use bytes::Bytes;
use std::collections::HashMap;

impl ConnectionState {
    pub(crate) fn drain(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for dir in self
            .dirs
            .iter_mut()
            .flatten()
            .chain(self.pending.iter_mut())
        {
            let pending = dir.buffer.len();
            dir.buffer.consume(pending);
            dir.release_all(context)?;
            dir.decoder = None;
            dir.block_sources = HashMap::new();
            dir.chain = None;
        }
        for msg in self
            .streams
            .values_mut()
            .flat_map(|stream| stream.msgs.iter_mut().flatten())
            .chain(self.parent_deferred.iter_mut())
            .chain(self.ack_deferred.iter_mut().map(|(_, msg, _)| msg))
        {
            context.release_all(&mut msg.charge)?;
        }
        self.parent_deferred.clear();
        self.ack_deferred.clear();
        if let Some(mut prelude) = self.prelude.take() {
            for side in Side::BOTH {
                context.release_all(&mut prelude.body_charge[side])?;
            }
            for mut msg in [prelude.live_request, prelude.live_response]
                .into_iter()
                .flatten()
                .chain(prelude.offers.into_values().filter_map(|offer| offer.msg))
            {
                context.release_all(&mut msg.charge)?;
            }
        }
        self.final_pending_settings.get_or_insert(
            self.settings
                .iter()
                .map(|direction| direction.pending.len() as u64)
                .sum(),
        );
        for direction in self.settings.iter_mut() {
            for mut pending in direction.pending.drain(..) {
                context.release_all(&mut pending.charge)?;
            }
        }
        self.final_pending_pings.get_or_insert(
            self.pings
                .iter()
                .map(|pings| pings.values().sum::<u64>())
                .sum::<u64>(),
        );
        for pings in self.pings.iter_mut() {
            pings.clear();
        }
        self.streams.clear();
        self.closed.clear();
        self.early_response_headers.clear();
        self.pending_openers.clear();
        self.closed_credit.clear();
        context.release_all(&mut self.charge)
    }

    pub(crate) fn close(
        &mut self,
        flow: &ScopedFlowKey,
        reset: bool,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if reset {
            return self.terminate(
                flow,
                Status::Reset,
                IssueCode::ConnectionReset,
                "the TCP connection reset",
                context,
            );
        }
        if !self.has_flow(flow) && self.has_flow(&flow.reverse()) {
            context.charge(&mut self.charge, budget::DIR_OVERHEAD)?;
            let mut dir = super::DirectionState::new(flow.clone());
            dir.closed = true;
            if let Some(reverse) = self.side_of(&flow.reverse()) {
                dir.phase = match self.phase {
                    Phase::H2 => DirectionPhase::Frames,
                    Phase::Prelude => DirectionPhase::Prelude,
                    _ => DirectionPhase::Sniff,
                };
                self.dirs[reverse.peer()] = Some(dir);
            } else {
                self.pending.push(dir);
            }
        }
        if let Some(dir) = self.dir_mut(flow) {
            dir.closed = true;
        }
        if self.phase == Phase::H2 {
            self.pump(context)?;
        }
        if self.phase == Phase::H2
            && let Some(side) = self.side_of(flow)
            && let Some(dir) = self.dirs[side].as_mut()
            && dir.buffer.is_empty()
            && dir.chain.is_none()
            && dir.phase == DirectionPhase::Frames
        {
            dir.fully_consumed_fin = true;
            if self.clean_start {
                self.reconcile_pending_openers(side, context)?;
                if self.phase == Phase::Dead {
                    return Ok(());
                }
            }
        }
        if let Some(side) = self.side_of(flow)
            && self.send_window[side] > super::super::settings::WINDOW_MAX
            && self.dirs[side]
                .as_ref()
                .is_some_and(|dir| dir.buffer.is_empty())
            && self.phase == Phase::H2
        {
            self.reject(context, Fault::new(flow.clone(), IssueScope::Connection, Status::Malformed, IssueCode::ConnectionWindowOverflow, "connection flow window remains above 2^31-1 after sender FIN; earlier WINDOW_UPDATE evidence is retained").stream(Some(0)))?;
            return Ok(());
        }
        if let Some(grant) = self.side_of(flow) {
            self.reconcile_closed_credit(grant.peer(), None, context)?;
            if self.phase == Phase::Dead {
                return Ok(());
            }
        }
        if let Some(side) = self.side_of(flow)
            && self.phase == Phase::H2
            && self.dirs[side]
                .as_ref()
                .is_some_and(|dir| dir.buffer.is_empty() && dir.chain.is_none())
        {
            if side == Side::Client
                && self.clean_start
                && let Some(parent) = self.parent_deferred.front().and_then(|msg| msg.promised_by)
            {
                self.reject(context, Fault::new(self.dir_flow(Side::Server), IssueScope::Connection, Status::Malformed, IssueCode::PushPromiseClosedParent, "client FIN proves the pending promise has no parent opener; promise evidence is retained in its message").stream(Some(parent)))?;
                return Ok(());
            }
            // Check before truncation handling discards any undecoded bytes.
            // A clean sender FIN excludes future DATA that could lower credit.
            let mut cursor = 0;
            loop {
                context.check_deadline()?;
                let Some(id) = self
                    .streams
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(id, _)| *id)
                else {
                    break;
                };
                cursor = id;
                self.confirm_stream_window_overflow(side, id, context)?;
            }
        }
        let deferred_ack = self
            .side_of(flow)
            .is_some_and(|side| self.waiting_settings_ack(side));
        if self.side_of(flow) == Some(Side::Server) {
            self.report_unmatched_response_at_eof(context)?;
        }
        let mut faults = Vec::new();
        if let Some(dir) = self.dir_mut(flow) {
            dir.closed = true;
            let phase = dir.phase;
            let partial = dir.buffer.len();
            if partial > 0 && !deferred_ack {
                let sets = dir.buffer.contributors(partial);
                let (wire, dropped) = dir.buffer.take(partial);
                let sources = union_balanced(sets)?;
                dir.release_consumed(partial, dropped, context)?;
                let detail = match phase {
                    DirectionPhase::Sniff => "connection closed before startup was determined",
                    DirectionPhase::Prelude => "connection closed mid HTTP/1 exchange",
                    DirectionPhase::Preface => "connection closed inside the client preface",
                    DirectionPhase::Frames => "connection closed mid-frame",
                };
                faults.push(
                    Fault::new(
                        dir.flow.clone(),
                        IssueScope::Capture,
                        Status::Incomplete,
                        IssueCode::TruncatedStream,
                        detail,
                    )
                    .evidence(wire, sources),
                );
            }
            if let Some(mut chain) = dir.chain.take() {
                context.release_all(&mut chain.charge)?;
                faults.push(
                    Fault::new(
                        dir.flow.clone(),
                        IssueScope::Capture,
                        Status::Incomplete,
                        IssueCode::TruncatedHeaderBlock,
                        "connection closed inside a header block",
                    )
                    .stream(Some(chain.stream_id))
                    .evidence(
                        Bytes::copy_from_slice(&chain.bytes),
                        union_balanced(chain.sets)?,
                    ),
                );
            }
        }
        for fault in faults {
            self.issue(context, fault)?;
        }
        if let Some(side) = self.side_of(flow) {
            let ids: Vec<u32> = self
                .streams
                .iter()
                .filter(|(_, s)| s.msgs[side].is_some() && !s.ended[side])
                .map(|(id, _)| *id)
                .collect();
            let flushed = !ids.is_empty();
            for id in ids {
                self.end_side(side, id, Status::Incomplete, context)?;
            }
            if flushed {
                self.worst(Status::Incomplete);
            }
            self.maybe_done(context)?;
        }
        Ok(())
    }

    fn maybe_done(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        if self
            .dirs
            .iter()
            .all(|d| d.as_ref().is_some_and(|d| d.closed))
            && self
                .streams
                .values()
                .all(|s| s.msgs.iter().all(Option::is_none))
        {
            self.done = true;
            if self
                .streams
                .values()
                .any(|stream| !stream.ended.all(|ended| *ended))
            {
                self.worst(Status::Incomplete);
            }
            for dir in self.dirs.iter_mut().flatten() {
                dir.release_all(context)?;
                dir.decoder = None;
                dir.block_sources.clear();
            }
        }
        Ok(())
    }

    pub(crate) fn terminate(
        &mut self,
        flow: &ScopedFlowKey,
        status: Status,
        code: IssueCode,
        detail: &'static str,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if (self.done || matches!(self.phase, Phase::Dead)) && code == IssueCode::TcpEvicted {
            return Ok(());
        }
        self.issue(
            context,
            Fault::new(flow.clone(), IssueScope::Capture, status, code, detail),
        )?;
        self.clean_start = false;
        self.report_unmatched_response_at_eof(context)?;
        let mut partials: Vec<(ScopedFlowKey, Option<u32>, Bytes, Option<SourceSet>)> = Vec::new();
        for dir in self
            .dirs
            .iter_mut()
            .flatten()
            .chain(self.pending.iter_mut())
        {
            let partial = dir.buffer.len();
            if partial > 0 {
                let sets = dir.buffer.contributors(partial);
                let (wire, dropped) = dir.buffer.take(partial);
                let sources = union_balanced(sets)?;
                dir.release_consumed(partial, dropped, context)?;
                partials.push((dir.flow.clone(), None, wire, sources));
            }
            if let Some(mut chain) = dir.chain.take() {
                context.release_all(&mut chain.charge)?;
                let sources = union_balanced(std::mem::take(&mut chain.sets))?;
                partials.push((
                    dir.flow.clone(),
                    Some(chain.stream_id),
                    Bytes::copy_from_slice(&chain.bytes),
                    sources,
                ));
            }
        }
        for (flow, stream_id, wire, sources) in partials {
            let (code, detail) = if stream_id.is_some() {
                (
                    IssueCode::TruncatedHeaderBlock,
                    "the byte stream ended inside a header block",
                )
            } else {
                (
                    IssueCode::UnconsumedBytes,
                    "the byte stream ended with undecoded bytes",
                )
            };
            self.issue(
                context,
                Fault::new(flow, IssueScope::Capture, status, code, detail)
                    .stream(stream_id)
                    .evidence(wire, sources),
            )?;
        }
        self.flush_messages(status, context)?;
        self.fail(context, status)
    }

    pub(crate) fn fail(&mut self, context: &mut Context<'_>, status: Status) -> Result<(), Error> {
        self.worst(status);
        self.phase = Phase::Dead;
        let mut faults = Vec::new();
        for dir in self.dirs.iter_mut().flatten() {
            if let Some(mut chain) = dir.chain.take() {
                context.release_all(&mut chain.charge)?;
                faults.push((
                    dir.flow.clone(),
                    chain.stream_id,
                    Bytes::copy_from_slice(&chain.bytes),
                    chain.sets,
                ));
            }
        }
        for (flow, stream_id, wire, sets) in faults {
            self.issue(
                context,
                Fault::new(
                    flow,
                    IssueScope::Capture,
                    status,
                    IssueCode::TruncatedHeaderBlock,
                    "the connection failed inside a header block",
                )
                .stream(Some(stream_id))
                .evidence(wire, union_balanced(sets)?),
            )?;
        }
        self.flush_messages(status, context)?;
        Ok(())
    }
}
