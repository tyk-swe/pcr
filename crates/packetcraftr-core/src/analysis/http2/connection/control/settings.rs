// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SETTINGS frame updates and acknowledgments.

use super::super::super::Error;
use super::super::super::buffer::union_balanced;
use super::super::super::model::{Certainty, Status};
use super::super::super::settings::{self, PendingSettings};
use super::super::super::stream::Phase as StreamPhase;
use super::super::{ActiveState, Context, Evidence, Fault, Reporter, StepAbort, StepResult};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http2 as wire;

impl ActiveState {
    pub(crate) fn settings_frame(
        &mut self,
        side: Side,
        flags: u8,
        settings: Vec<wire::Setting>,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if flags & wire::FLAG_ACK != 0 {
            self.handle_settings_ack(side, evidence, reporter, context)
        } else {
            self.handle_settings_update(side, &settings, evidence, reporter, context)
        }
    }

    fn handle_settings_ack(
        &mut self,
        side: Side,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let Some(mut acked) = self.control.settings[side.peer()].acknowledge() else {
            return self.report_unsolicited_settings_ack(side, evidence, reporter, context);
        };
        let overflow = self.apply_acked_stream_windows(side, &acked, context)?;
        acked.window_grants = std::collections::BTreeMap::new();
        context.release_all(&mut acked.charge)?;
        self.streams
            .apply_settings_delta_to_closed_credit(side, acked.window_delta, context)?;
        if overflow {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::WindowOverflow,
                    "SETTINGS window change pushed a stream window out of range",
                )
                .with_evidence(evidence.wire, evidence.sources),
            );
        }
        self.sync_decoder_after_ack(side, &acked, context)?;
        self.reconcile_closed_credit(side, None, reporter, context)?;
        self.release_ack_deferred_messages(reporter, context)
    }

    fn report_unsolicited_settings_ack(
        &self,
        side: Side,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        // Two unmatched ACK heads cannot be explained by reordering:
        // both matching SETTINGS would have to precede the other's ACK.
        // Retain the peer's still-buffered evidence before failure drains it.
        let peer_ack = self
            .directions
            .get(side.peer())
            .filter(|dir| {
                self.control.settings[side].pending.is_empty() && dir.has_buffered_settings_ack()
            })
            .map(|dir| {
                (
                    bytes::Bytes::copy_from_slice(&dir.buffer.bytes()[..wire::HEADER_LEN]),
                    dir.buffer.contributors(wire::HEADER_LEN),
                )
            });
        let confirmed = self.clean_start
            && (peer_ack.is_some()
                || self
                    .directions
                    .get(side.peer())
                    .is_some_and(|dir| dir.buffer.is_empty()));
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
                IssueCode::UnsolicitedSettingsAck,
                "a SETTINGS acknowledgment does not match a pending SETTINGS",
            )
            .with_certainty(certainty)
            .with_evidence(evidence.wire, evidence.sources),
        )?;
        if let Some((wire, sets)) = peer_ack {
            reporter.issue(
                context,
                Fault::connection(
                    self.directions.flow(side.peer()),
                    status,
                    IssueCode::UnsolicitedSettingsAck,
                    "both directional ACK heads lack preceding matching SETTINGS",
                )
                .with_certainty(certainty)
                .with_evidence(wire, union_balanced(sets)?),
            )?;
        }
        Err(StepAbort::ConnectionFailed(status))
    }

    fn apply_acked_stream_windows(
        &mut self,
        side: Side,
        acked: &PendingSettings,
        context: &Context<'_>,
    ) -> Result<bool, Error> {
        let mut overflow = false;
        let peer = side.peer();
        for (id, stream) in self.streams.open_iter_mut() {
            context.check_deadline()?;
            if stream.phase == StreamPhase::Closed {
                continue;
            }
            let existed = stream.initiator != peer || id <= acked.sender_stream_limit;
            let later_grants =
                stream.window_granted[side] - acked.window_grants.get(&id).copied().unwrap_or(0);
            // Grants following SETTINGS cannot have taken effect before
            // its immediate ACK, even if capture order shows them first.
            if existed
                && acked.peak_window_delta.is_some_and(|peak| {
                    stream.send_window[side] - later_grants + peak > settings::WINDOW_MAX
                })
            {
                overflow = true;
            }
            if stream.send_window[side] + acked.window_delta.max(0) >= 0 {
                stream.credit_exceeded[side] = false;
            }
            stream.send_window[side] += acked.window_delta;
        }
        Ok(overflow)
    }

    fn sync_decoder_after_ack(
        &mut self,
        side: Side,
        acked: &PendingSettings,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let peer = side.peer();
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(());
        };
        if let Some(decoder) = dir.decoder.as_mut() {
            if let Some(minimum) = acked.minimum_table_size {
                if acked.possibly_applied_table_minimum {
                    let uncertain = &mut self.control.settings[peer].uncertain_table_minimum;
                    *uncertain = Some(uncertain.map_or(minimum, |old| old.min(minimum)));
                } else {
                    decoder.acknowledge_table_size(minimum)?;
                }
            }
            decoder.acknowledge_table_size(acked.final_values.header_table_size)?;
            for pending in &self.control.settings[peer].pending {
                decoder.permit_table_size(pending.final_values.header_table_size);
            }
        }
        dir.sync_decoder(context)
    }

    fn handle_settings_update(
        &mut self,
        side: Side,
        settings: &[wire::Setting],
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if self.control.settings[side].pending.len() + 1 > context.limits.max_pending_settings {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Limit,
                    IssueCode::PendingSettings,
                    "unacknowledged SETTINGS frames exceed the configured bound",
                )
                .with_evidence(evidence.wire, evidence.sources),
            );
        }
        let peer = side.peer();
        let resume_peer = self.waiting_settings_ack(peer);
        let applied = self.control.settings[side].apply(settings, side == Side::Server);
        let mut pending = applied.pending;
        pending.sender_stream_limit = self.streams.max_initiated(side);
        context.charge(
            &mut pending.charge,
            budget::PENDING_OVERHEAD
                + self
                    .streams
                    .open_len()
                    .saturating_mul(budget::CLOSED_STREAM_OVERHEAD),
        )?;
        for (id, stream) in self.streams.open_iter() {
            context.check_deadline()?;
            pending
                .window_grants
                .insert(id, stream.window_granted[peer]);
        }
        let advertised_table_size = pending.final_values.header_table_size;
        self.control.settings[side].pending.push_back(pending);
        if let Some(decoder) = self
            .directions
            .get_mut(peer)
            .and_then(|dir| dir.decoder.as_mut())
        {
            decoder.permit_table_size(advertised_table_size);
        }
        if !applied.issues.is_empty() {
            let flow = self.directions.flow(side);
            for issue in applied.issues {
                reporter.issue(
                    context,
                    Fault::connection(flow.clone(), Status::Malformed, issue.code, issue.detail)
                        .with_evidence_ref(&evidence),
                )?;
            }
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        if resume_peer {
            self.deferred.resume_side = Some(peer);
        }
        Ok(())
    }
}
