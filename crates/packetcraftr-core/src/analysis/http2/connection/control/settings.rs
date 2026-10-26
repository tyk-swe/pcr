// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SETTINGS application and acknowledgments.

use super::super::super::model::{Certainty, IssueScope, Status};
use super::super::super::stream::Phase as StreamPhase;
use super::super::super::{Error, settings};
use super::super::{ConnectionState, Context, Evidence, Fault};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http2 as wire;

impl ConnectionState {
    pub(crate) fn settings_frame(
        &mut self,
        side: Side,
        flags: u8,
        settings: Vec<wire::Setting>,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if flags & wire::FLAG_ACK != 0 {
            let Some(mut acked) = self.settings[side.peer()].acknowledge() else {
                // Two unmatched ACK heads cannot be explained by reordering:
                // both matching SETTINGS would have to precede the other's ACK.
                // Retain the peer's still-buffered evidence before failure drains it.
                let peer_ack = self.dirs[side.peer()]
                    .as_ref()
                    .filter(|dir| {
                        let bytes = dir.buffer.bytes();
                        self.settings[side].pending.is_empty()
                            && dir.saw_frame
                            && dir.chain.is_none()
                            && bytes.len() >= wire::HEADER_LEN
                            && wire::declared_length(bytes) == 0
                            && bytes[3] == wire::TYPE_SETTINGS
                            && bytes[4] & wire::FLAG_ACK != 0
                            && bytes[5] & 0x7f == 0
                            && bytes[6..9] == [0, 0, 0]
                    })
                    .map(|dir| {
                        (
                            bytes::Bytes::copy_from_slice(&dir.buffer.bytes()[..wire::HEADER_LEN]),
                            dir.buffer.contributors(wire::HEADER_LEN),
                        )
                    });
                let confirmed = self.clean_start
                    && (peer_ack.is_some()
                        || self.dirs[side.peer()]
                            .as_ref()
                            .is_some_and(|dir| dir.buffer.is_empty()));
                let status = if confirmed {
                    Status::Malformed
                } else {
                    Status::Incomplete
                };
                self.issue(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Connection,
                        status,
                        IssueCode::UnsolicitedSettingsAck,
                        "a SETTINGS acknowledgment does not match a pending SETTINGS",
                    )
                    .certainty(if confirmed {
                        Certainty::Confirmed
                    } else {
                        Certainty::Indeterminate
                    })
                    .evidence(evidence.wire, evidence.sources),
                )?;
                if let Some((wire, sets)) = peer_ack {
                    self.issue(
                        context,
                        Fault::new(
                            self.dir_flow(side.peer()),
                            IssueScope::Connection,
                            status,
                            IssueCode::UnsolicitedSettingsAck,
                            "both directional ACK heads lack preceding matching SETTINGS",
                        )
                        .certainty(if confirmed {
                            Certainty::Confirmed
                        } else {
                            Certainty::Indeterminate
                        })
                        .evidence(wire, super::super::super::buffer::union_balanced(sets)?),
                    )?;
                }
                self.fail(context, status)?;
                return Ok(());
            };
            let mut overflow = false;
            for (id, stream) in &mut self.streams {
                context.check_deadline()?;
                if stream.phase != StreamPhase::Closed {
                    let owner = if stream.initiator == Side::Client {
                        Side::Client
                    } else {
                        Side::Server
                    };
                    let existed = owner != side.peer() || *id <= acked.sender_stream_limit;
                    let later_grants = stream.window_granted[side]
                        - acked.window_grants.get(id).copied().unwrap_or(0);
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
            }
            drop(acked.window_grants);
            context.release_all(&mut acked.charge)?;
            for debt in self.closed_credit.values_mut() {
                context.check_deadline()?;
                if let Some(window) = debt[side].as_mut() {
                    *window += acked.window_delta;
                    if *window >= 0 {
                        debt[side] = None;
                    }
                }
            }
            self.release_resolved_credit(context)?;
            if overflow {
                self.reject(
                    context,
                    Fault::new(
                        self.dir_flow(side),
                        IssueScope::Connection,
                        Status::Malformed,
                        IssueCode::WindowOverflow,
                        "SETTINGS window change pushed a stream window out of range",
                    )
                    .evidence(evidence.wire.clone(), evidence.sources.clone()),
                )?;
                return Ok(());
            }
            if let Some(dir) = self.dirs[side].as_mut()
                && let Some(decoder) = dir.decoder.as_mut()
            {
                if let Some(minimum) = acked.minimum_table_size {
                    if acked.possibly_applied_table_minimum {
                        let uncertain = &mut self.settings[side.peer()].uncertain_table_minimum;
                        *uncertain = Some(uncertain.map_or(minimum, |old| old.min(minimum)));
                    } else {
                        decoder.acknowledge_table_size(minimum)?;
                    }
                }
                decoder.acknowledge_table_size(acked.values.header_table_size)?;
                for pending in &self.settings[side.peer()].pending {
                    decoder.permit_table_size(pending.final_values.header_table_size);
                }
            }
            self.decoder_sync(side, context)?;
            self.reconcile_closed_credit(side, None, context)?;
            self.release_ack_deferred_messages(context)?;
            return Ok(());
        }
        if self.settings[side].pending.len() + 1 > context.limits.max_pending_settings {
            let flow = self.dir_flow(side);
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Limit,
                    IssueCode::PendingSettings,
                    "unacknowledged SETTINGS frames exceed the configured bound",
                )
                .evidence(evidence.wire, evidence.sources),
            )?;
            return Ok(());
        }
        let resume_peer = self.waiting_settings_ack(side.peer());
        let applied = self.settings[side].apply(&settings, side == Side::Server);
        let mut pending = applied.pending;
        pending.sender_stream_limit = self.max_initiated[side];
        context.charge(
            &mut pending.charge,
            budget::PENDING_OVERHEAD
                + self
                    .streams
                    .len()
                    .saturating_mul(budget::CLOSED_STREAM_OVERHEAD),
        )?;
        for (id, stream) in &self.streams {
            context.check_deadline()?;
            pending
                .window_grants
                .insert(*id, stream.window_granted[side.peer()]);
        }
        let advertised_table_size = pending.final_values.header_table_size;
        self.settings[side].pending.push_back(pending);
        if let Some(decoder) = self.dirs[side.peer()]
            .as_mut()
            .and_then(|dir| dir.decoder.as_mut())
        {
            decoder.permit_table_size(advertised_table_size);
        }
        let issues = applied.issues;
        let invalid = !issues.is_empty();
        for issue in issues {
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(side),
                    IssueScope::Connection,
                    Status::Malformed,
                    issue.code,
                    issue.detail,
                )
                .evidence(evidence.wire.clone(), evidence.sources.clone()),
            )?;
        }
        if invalid {
            self.fail(context, Status::Malformed)?;
        } else if resume_peer {
            self.resume_side = Some(side.peer());
        }
        Ok(())
    }
}
