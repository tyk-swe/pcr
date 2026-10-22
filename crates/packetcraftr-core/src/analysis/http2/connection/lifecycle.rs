// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection shutdown: draining, closing, termination, and failure.

mod teardown;

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Status};
use super::super::stream::{CLIENT, SERVER};
use super::{ConnectionState, Context, DirectionPhase, Fault, Phase, resources};
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use bytes::Bytes;
use std::collections::HashMap;

impl ConnectionState {
    pub(crate) fn drain(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let mut bytes = self.live - self.upgrade_charge;
        let mut spans = 0usize;
        for dir in self
            .dirs
            .iter_mut()
            .flatten()
            .chain(self.pending.iter_mut())
        {
            let pending = dir.buffer.len();
            let dropped = dir.buffer.discard(pending);
            let _ = dropped;
            bytes += dir.charged;
            spans += dir.charged_spans;
            dir.charged = 0;
            dir.charged_spans = 0;
            dir.decoder = None;
            dir.decoder_charge = 0;
            dir.block_sources = HashMap::new();
            dir.chain = None;
        }
        for stream in self.streams.values_mut() {
            for msg in stream.msgs.iter_mut().flatten() {
                spans += msg.charged_spans;
            }
        }
        if let Some(prelude) = self.prelude.as_mut() {
            for slot in [
                prelude.live_request.as_mut(),
                prelude.live_response.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                spans += slot.charged_spans;
            }
            for offer in prelude.offers.values_mut() {
                if let Some(msg) = offer.msg.as_mut() {
                    spans += msg.charged_spans;
                }
            }
        }
        self.final_pending_settings.get_or_insert(
            self.settings
                .iter()
                .map(|direction| direction.pending.len() as u64)
                .sum(),
        );
        for direction in self.settings.iter_mut() {
            direction.pending.clear();
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
        self.live = self.upgrade_charge;
        self.streams.clear();
        self.closed.clear();
        self.early_response_headers.clear();
        self.pending_openers.clear();
        self.closed_credit.clear();
        self.prelude = None;
        context.release_live(bytes);
        *context.spans = context.spans.checked_sub(spans).expect("span release");
        Ok(())
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
                "connection_reset",
                "the TCP connection reset",
                context,
            );
        }
        if !self.has_flow(flow) && self.has_flow(&flow.reverse()) {
            self.charge_conn(context, resources::DIR_OVERHEAD)?;
            let mut dir = super::DirectionState::new(flow.clone());
            dir.closed = true;
            if let Some(reverse) = self.side_of(&flow.reverse()) {
                dir.phase = match self.phase {
                    Phase::H2 => DirectionPhase::Frames,
                    Phase::Prelude => DirectionPhase::Prelude,
                    _ => DirectionPhase::Sniff,
                };
                self.dirs[1 - reverse] = Some(dir);
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
            self.issue(context, Fault {
                flow: flow.clone(),
                http2_stream_id: Some(0),
                scope: IssueScope::Connection,
                certainty: Certainty::Confirmed,
                status: Status::Malformed,
                code: "connection_window_overflow",
                detail: "connection flow window remains above 2^31-1 after sender FIN; earlier WINDOW_UPDATE evidence is retained".into(),
                wire: Bytes::new(),
                sources: None,
            })?;
            self.fail(context, Status::Malformed)?;
            return Ok(());
        }
        if let Some(grant) = self.side_of(flow) {
            self.reconcile_closed_credit(1 - grant, None, context)?;
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
            if side == CLIENT
                && self.clean_start
                && let Some(parent) = self.parent_deferred.front().and_then(|msg| msg.promised_by)
            {
                self.issue(context, Fault {
                    flow: self.dir_flow(SERVER),
                    http2_stream_id: Some(parent),
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "push_promise_closed_parent",
                    detail: "client FIN proves the pending promise has no parent opener; promise evidence is retained in its message".into(),
                    wire: Bytes::new(),
                    sources: None,
                })?;
                self.fail(context, Status::Malformed)?;
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
        if self.side_of(flow) == Some(SERVER) {
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
                Self::release_dir(dir, context, partial);
                Self::release_dropped(dir, dropped, context);
                let detail = match phase {
                    DirectionPhase::Sniff => "connection closed before startup was determined",
                    DirectionPhase::Prelude => "connection closed mid HTTP/1 exchange",
                    DirectionPhase::Preface => "connection closed inside the client preface",
                    DirectionPhase::Frames => "connection closed mid-frame",
                };
                faults.push(Fault {
                    flow: dir.flow.clone(),
                    http2_stream_id: None,
                    scope: IssueScope::Capture,
                    certainty: Certainty::Confirmed,
                    status: Status::Incomplete,
                    code: "truncated_stream",
                    detail: detail.into(),
                    wire,
                    sources,
                });
            }
            if let Some(chain) = dir.chain.take() {
                Self::release_dir(dir, context, chain.charged);
                dir.charged_spans -= chain.charged_spans;
                *context.spans = context
                    .spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
                faults.push(Fault {
                    flow: dir.flow.clone(),
                    http2_stream_id: Some(chain.stream_id),
                    scope: IssueScope::Capture,
                    certainty: Certainty::Confirmed,
                    status: Status::Incomplete,
                    code: "truncated_header_block",
                    detail: "connection closed inside a header block".into(),
                    wire: Bytes::copy_from_slice(&chain.bytes),
                    sources: union_balanced(chain.sets)?,
                });
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
            self.maybe_done(context);
        }
        Ok(())
    }

    fn maybe_done(&mut self, context: &mut Context<'_>) {
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
                .any(|stream| stream.ended != [true, true])
            {
                self.worst(Status::Incomplete);
            }
            for dir in self.dirs.iter_mut().flatten() {
                context.release_live(dir.charged);
                *context.spans -= dir.charged_spans;
                dir.charged = 0;
                dir.charged_spans = 0;
                dir.decoder = None;
                dir.decoder_charge = 0;
                dir.block_sources.clear();
            }
        }
    }

    pub(crate) fn terminate(
        &mut self,
        flow: &ScopedFlowKey,
        status: Status,
        code: &'static str,
        detail: &'static str,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if (self.done || matches!(self.phase, Phase::Dead)) && matches!(code, "tcp_evicted") {
            return Ok(());
        }
        self.issue(
            context,
            Fault {
                flow: flow.clone(),
                http2_stream_id: None,
                scope: IssueScope::Capture,
                certainty: Certainty::Confirmed,
                status,
                code,
                detail: detail.into(),
                wire: Bytes::new(),
                sources: None,
            },
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
                Self::release_dir(dir, context, partial);
                Self::release_dropped(dir, dropped, context);
                partials.push((dir.flow.clone(), None, wire, sources));
            }
            if let Some(mut chain) = dir.chain.take() {
                Self::release_dir(dir, context, chain.charged);
                dir.charged_spans -= chain.charged_spans;
                *context.spans = context
                    .spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
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
                    "truncated_header_block",
                    "the byte stream ended inside a header block",
                )
            } else {
                (
                    "unconsumed_bytes",
                    "the byte stream ended with undecoded bytes",
                )
            };
            self.issue(
                context,
                Fault {
                    flow,
                    http2_stream_id: stream_id,
                    scope: IssueScope::Capture,
                    certainty: Certainty::Confirmed,
                    status,
                    code,
                    detail: detail.into(),
                    wire,
                    sources,
                },
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
            if let Some(chain) = dir.chain.take() {
                Self::release_dir(dir, context, chain.charged);
                dir.charged_spans = dir
                    .charged_spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
                *context.spans = context
                    .spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
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
                Fault {
                    flow,
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Capture,
                    certainty: Certainty::Confirmed,
                    status,
                    code: "truncated_header_block",
                    detail: "the connection failed inside a header block".into(),
                    wire,
                    sources: union_balanced(sets)?,
                },
            )?;
        }
        self.flush_messages(status, context)?;
        Ok(())
    }
}
