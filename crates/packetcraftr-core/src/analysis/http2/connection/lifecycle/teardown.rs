// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Partial-message flushing, final status classification, and connection publication.

use super::super::reporter::ConnectionSnapshot;
use super::super::{
    ActiveState, ConnectionState, Context, DirectionPhase, Fault, Phase, Reporter,
    SniffingDirections, SniffingState, StepAbort,
};
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::model::{Certainty, Startup, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::{Error, IssueCode};

impl ActiveState {
    pub(crate) fn flush_messages(
        &mut self,
        status: Status,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<usize, Error> {
        let mut pending_msgs = Vec::new();
        for msg in self.deferred.take_all_promises(context)? {
            pending_msgs.push((Side::Server, msg));
        }
        for (side, msg, _) in self.deferred.take_all_awaiting_ack(context)? {
            pending_msgs.push((side, msg));
        }
        pending_msgs.extend(self.streams.drain_open_messages());

        let mut upgrade_evidence = Vec::new();
        let mut release = Vec::new();
        if let Some(prelude) = self.prelude.as_mut() {
            if let Some(mut msg) = prelude.sides[Side::Client].live_message.take() {
                if prelude.offers.contains_key(&msg.index) {
                    if prelude.upgraded {
                        msg.stream_id = 1;
                        pending_msgs.push((Side::Client, msg));
                    } else {
                        upgrade_evidence.push(msg);
                    }
                } else {
                    release.push(msg);
                }
            }
            release.extend(prelude.sides[Side::Server].live_message.take());
            for offer in prelude.offers.values_mut() {
                if let Some(mut msg) = offer.msg.take() {
                    if prelude.upgraded {
                        msg.stream_id = 1;
                        pending_msgs.push((Side::Client, msg));
                    } else {
                        upgrade_evidence.push(msg);
                    }
                }
            }
        }
        for mut msg in upgrade_evidence {
            let head = msg
                .upgrade_head
                .take()
                .ok_or(Error::Invariant("upgrade request head"))?;
            let sources = union_balanced(std::mem::take(&mut msg.sets))?;
            context.release_all(&mut msg.charge)?;
            reporter.issue(
                context,
                Fault::capture(
                    self.directions.flow(Side::Client),
                    status,
                    IssueCode::IncompleteUpgrade,
                    "the byte stream ended before the h2c upgrade completed",
                )
                .with_evidence(head.wire().clone(), sources),
            )?;
        }
        for mut msg in release {
            context.release_all(&mut msg.charge)?;
        }
        let emitted = pending_msgs.len();
        for (side, msg) in pending_msgs {
            self.emit_message(side, msg, status, reporter, context)?;
        }
        Ok(emitted)
    }

    fn audit_directions_at_finish(
        &mut self,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.settings_audited = true;
        for side in Side::BOTH {
            let Some(dir) = self.directions.get_mut(side) else {
                continue;
            };
            if !dir.buffer.is_empty() {
                let partial = dir.buffer.len();
                let (wire, sets) = dir.buffer.take(partial, context)?;
                let sources = union_balanced(sets)?;
                reporter.issue(
                    context,
                    Fault::capture(
                        dir.flow.clone(),
                        Status::Incomplete,
                        IssueCode::UnconsumedBytes,
                        "the capture ended with undecoded bytes",
                    )
                    .with_evidence(wire, sources),
                )?;
            }
            if !self.control.settings[side].seen
                && (self.clean_start || dir.saw_frame || !dir.buffer.is_empty())
            {
                reporter.issue(
                    context,
                    Fault::connection(
                        dir.flow.clone(),
                        Status::Incomplete,
                        IssueCode::SettingsUnobserved,
                        "the endpoint's initial SETTINGS were never observed",
                    )
                    .with_certainty(if self.clean_start {
                        Certainty::Confirmed
                    } else {
                        Certainty::Indeterminate
                    }),
                )?;
            }
        }
        Ok(())
    }

    fn classify_final_status(&self, reporter: &mut Reporter) {
        if self.is_h2() {
            let missing_frames = Side::BOTH.into_iter().any(|side| {
                self.directions
                    .get(side)
                    .is_none_or(|dir| dir.phase != DirectionPhase::Frames)
            });
            let missing_settings = self
                .control
                .settings
                .iter()
                .any(|direction| !direction.seen);
            if missing_frames || missing_settings || self.streams.has_unfinished_open_streams() {
                reporter.worst(Status::Incomplete);
            }
            if self.upgrade.refused {
                reporter.worst(Status::Unsupported);
            } else if self.directions.server.is_none() && reporter.frames > 0 {
                reporter.worst(Status::Incomplete);
            }
            return;
        }
        let no_pending_offers = self
            .prelude
            .as_ref()
            .is_none_or(|prelude| prelude.offers.is_empty());
        reporter.worst(
            if self.upgrade.refused || (self.done && no_pending_offers) {
                Status::Unsupported
            } else {
                Status::Incomplete
            },
        );
    }
}

impl ConnectionState {
    pub(crate) fn finish(mut self, context: &mut Context<'_>) -> Result<(), Error> {
        context.check_deadline()?;
        match &mut self.phase {
            Phase::Dead(_) => {}
            Phase::Sniffing(sniff) => {
                let candidates = &sniff.directions.candidates;
                let all_garbage = candidates.iter().any(|dir| dir.received)
                    && candidates.iter().all(|dir| !dir.received || dir.garbage);
                self.reporter.worst(
                    if self.reporter.startup == Startup::Unknown && all_garbage {
                        Status::Unsupported
                    } else {
                        Status::Incomplete
                    },
                );
                let flow = self.primary_flow();
                self.terminate(
                    &flow,
                    Status::Incomplete,
                    IssueCode::CaptureEnd,
                    "the capture ended before connection analysis completed",
                    context,
                )?;
            }
            Phase::Active(active) => {
                active.finalizing = true;
                let pump_result = if active.is_h2() {
                    active.pump(&mut self.reporter, context)
                } else {
                    Ok(())
                };
                match pump_result {
                    Ok(()) => self.finish_active(context)?,
                    Err(StepAbort::ConnectionFailed(status)) => {
                        self.fail_to_dead(status, context)?;
                    }
                    Err(StepAbort::Fatal(error)) => return Err(error),
                }
            }
        }
        self.emit_and_release_dead(context)
    }

    fn finish_active(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Phase::Active(active) = &mut self.phase else {
            return Ok(());
        };
        active.report_unmatched_response_at_eof(&mut self.reporter, context)?;
        active.audit_directions_at_finish(&mut self.reporter, context)?;
        active.classify_final_status(&mut self.reporter);
        if !active.done {
            let flow = active.directions.primary_flow();
            return self.terminate(
                &flow,
                Status::Incomplete,
                IssueCode::CaptureEnd,
                "the capture ended before connection analysis completed",
                context,
            );
        }
        let flushed = active.flush_messages(Status::Incomplete, &mut self.reporter, context)?;
        if flushed > 0 {
            self.reporter.worst(Status::Incomplete);
        }
        let placeholder = Phase::Sniffing(SniffingState {
            directions: SniffingDirections::new(),
        });
        if let Phase::Active(active) = std::mem::replace(&mut self.phase, placeholder) {
            let dead = active.into_dead(None, &mut self.reporter, context)?;
            self.phase = Phase::Dead(Box::new(dead));
        }
        Ok(())
    }

    fn emit_and_release_dead(mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Phase::Dead(mut dead) = self.phase else {
            return Err(Error::Invariant("finish must reach dead state"));
        };
        for (flow, certainty) in dead.unobserved_settings {
            self.reporter.issue(
                context,
                Fault::connection(
                    flow,
                    Status::Incomplete,
                    IssueCode::SettingsUnobserved,
                    "the endpoint's initial SETTINGS were never observed",
                )
                .with_certainty(certainty),
            )?;
        }
        let snapshot = ConnectionSnapshot {
            flow: dead.flow,
            client_settings: dead.client_settings,
            server_settings: dead.server_settings,
            client_window: dead.client_window,
            server_window: dead.server_window,
            streams: dead.streams_admitted,
            pending_settings: dead.pending.settings,
            pending_pings: dead.pending.pings,
            upgrade_response: dead.upgrade.response.take(),
            upgrade_sources: dead.upgrade.sources.take(),
            upgrade_charge: dead.upgrade.charge,
        };
        self.reporter.emit_connection(snapshot, context)?;
        context.release_all(&mut dead.overhead)
    }
}
