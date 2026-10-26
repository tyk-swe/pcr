// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Partial-message flushing, final resource teardown, and connection publication.

use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;

use crate::analysis::http2::Error;
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::connection::{ConnectionState, Context, DirectionPhase, Fault, Phase};
use crate::analysis::http2::model::{Certainty, Connection, IssueScope, Startup, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::Phase as StreamPhase;

impl ConnectionState {
    pub(crate) fn flush_messages(
        &mut self,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<usize, Error> {
        let mut pending_msgs = Vec::new();
        let promises = std::mem::take(&mut self.deferred.promises);
        context.release(&mut self.charge, promises.len() * budget::PENDING_OVERHEAD)?;
        for msg in promises {
            pending_msgs.push((Side::Server, msg.stream_id, msg));
        }
        let immediate = std::mem::take(&mut self.deferred.awaiting_ack);
        context.release(&mut self.charge, immediate.len() * budget::PENDING_OVERHEAD)?;
        for (side, msg, _) in immediate {
            pending_msgs.push((side, msg.stream_id, msg));
        }

        for (id, stream) in self.streams.open.iter_mut() {
            for side in Side::BOTH {
                if let Some(msg) = stream.msgs[side].take() {
                    pending_msgs.push((side, *id, msg));
                }
            }
            stream.phase = StreamPhase::Closed;
        }
        let mut upgrade_evidence = Vec::new();
        let mut release = Vec::new();
        if let Some(prelude) = self.upgrade.prelude.as_mut() {
            if let Some(mut msg) = prelude.live_request.take() {
                if prelude.offers.contains_key(&msg.index) {
                    if prelude.upgraded {
                        msg.stream_id = 1;
                        pending_msgs.push((Side::Client, 1, msg));
                    } else {
                        upgrade_evidence.push(msg);
                    }
                } else {
                    release.push(msg);
                }
            }
            release.extend(prelude.live_response.take());
            for offer in prelude.offers.values_mut() {
                if let Some(mut msg) = offer.msg.take() {
                    if prelude.upgraded {
                        msg.stream_id = 1;
                        pending_msgs.push((Side::Client, 1, msg));
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
            self.issue(
                context,
                Fault::new(
                    self.dir_flow(Side::Client),
                    IssueScope::Capture,
                    status,
                    IssueCode::IncompleteUpgrade,
                    "the byte stream ended before the h2c upgrade completed",
                )
                .evidence(head.wire().clone(), sources),
            )?;
        }
        for mut msg in release {
            context.release_all(&mut msg.charge)?;
        }
        let emitted = pending_msgs.len();
        for (side, _, msg) in pending_msgs {
            self.emit_message(side, msg, status, context)?;
        }
        Ok(emitted)
    }

    pub(crate) fn release_prelude(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Some(mut prelude) = self.upgrade.prelude.take() else {
            return Ok(());
        };
        let mut release = prelude.requests.len() * budget::PENDING_OVERHEAD;
        release += prelude
            .offers
            .values()
            .map(|offer| budget::OFFER_OVERHEAD + offer.settings.capacity() * 24)
            .sum::<usize>();
        release += budget::DIR_OVERHEAD;
        context.release(&mut self.charge, release)?;
        for side in Side::BOTH {
            context.release_all(&mut prelude.body_charge[side])?;
        }
        for mut msg in [prelude.live_request, prelude.live_response]
            .into_iter()
            .flatten()
            .chain(prelude.offers.into_values().filter_map(|o| o.msg))
        {
            context.release_all(&mut msg.charge)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self, context: &mut Context<'_>) -> Result<(), Error> {
        context.check_deadline()?;
        self.finalizing = true;
        if self.phase == Phase::H2 {
            self.pump(context)?;
        }
        self.report_unmatched_response_at_eof(context)?;
        for side in Side::BOTH {
            if let Some(dir) = self.directions.get_mut(side) {
                if !dir.buffer.is_empty() && !matches!(self.phase, Phase::Dead) {
                    let partial = dir.buffer.len();
                    let sets = dir.buffer.contributors(partial);
                    let (wire, dropped) = dir.buffer.take(partial);
                    let sources = union_balanced(sets)?;
                    dir.release_consumed(partial, dropped, context)?;
                    let flow = dir.flow.clone();
                    self.issue(
                        context,
                        Fault::new(
                            flow,
                            IssueScope::Capture,
                            Status::Incomplete,
                            IssueCode::UnconsumedBytes,
                            "the capture ended with undecoded bytes",
                        )
                        .evidence(wire, sources),
                    )?;
                }
                if !self.control.settings[side].seen
                    && self.directions.get(side).is_some_and(|dir| {
                        self.clean_start || dir.saw_frame || !dir.buffer.is_empty()
                    })
                {
                    self.issue(
                        context,
                        Fault::new(
                            self.dir_flow(side),
                            IssueScope::Connection,
                            Status::Incomplete,
                            IssueCode::SettingsUnobserved,
                            "the endpoint's initial SETTINGS were never observed",
                        )
                        .certainty(if self.clean_start {
                            Certainty::Confirmed
                        } else {
                            Certainty::Indeterminate
                        }),
                    )?;
                }
            }
        }
        if !matches!(self.phase, Phase::Dead) {
            if matches!(self.phase, Phase::H2)
                && (Side::BOTH.into_iter().any(|side| {
                    self.directions
                        .get(side)
                        .is_none_or(|dir| dir.phase != DirectionPhase::Frames)
                }) || self
                    .control
                    .settings
                    .iter()
                    .any(|direction| !direction.seen)
                    || self
                        .streams
                        .open
                        .values()
                        .any(|stream| !stream.ended.all(|ended| *ended)))
            {
                self.worst(Status::Incomplete);
            }
            if self.directions.get(Side::Client).is_none() {
                let candidates = self.directions.candidates();
                let all_garbage = candidates.iter().any(|dir| dir.received)
                    && candidates.iter().all(|dir| !dir.received || dir.garbage);
                self.worst(if self.startup == Startup::Unknown && all_garbage {
                    Status::Unsupported
                } else {
                    Status::Incomplete
                });
            } else if matches!(self.phase, Phase::Prelude | Phase::Sniff) {
                self.worst(
                    if self.upgrade.refused
                        || (self.done
                            && self
                                .upgrade
                                .prelude
                                .as_ref()
                                .is_none_or(|prelude| prelude.offers.is_empty()))
                    {
                        Status::Unsupported
                    } else {
                        Status::Incomplete
                    },
                );
            } else if self.upgrade.prelude.is_some() && !self.upgrade.refused {
                self.worst(Status::Incomplete);
            } else if self.upgrade.refused {
                self.worst(Status::Unsupported);
            } else if self.directions.get(Side::Server).is_none() && self.frames > 0 {
                self.worst(Status::Incomplete);
            }
            if !self.done {
                let flow = self.flow();
                self.terminate(
                    &flow,
                    Status::Incomplete,
                    IssueCode::CaptureEnd,
                    "the capture ended before connection analysis completed",
                    context,
                )?;
            }
            let flushed = self.flush_messages(Status::Incomplete, context)?;
            if flushed > 0 {
                self.worst(Status::Incomplete);
            }
        }
        self.emit_connection(context)?;
        self.drain(context)?;
        Ok(())
    }

    pub(crate) fn emit_connection(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        if self.emitted {
            return Ok(());
        }
        self.emitted = true;
        let charge = budget::EVENT_OVERHEAD
            + budget::MESSAGE_OVERHEAD
            + self
                .upgrade
                .response
                .as_ref()
                .map_or(0, |head| head.wire().len())
            + self.upgrade.sources.as_ref().map_or(0, |set| {
                budget::SET_OVERHEAD + set.frames().len() * budget::SPAN_OVERHEAD
            });
        context.charge_retained(charge)?;
        let pending = self.control.pending_counts();
        context.connection(Connection {
            stream: self.stream,
            generation: self.generation,
            flow: self.flow(),
            startup: self.startup,
            status: self.status,
            client_settings: self.control.settings[Side::Client].advertised,
            server_settings: self.control.settings[Side::Server].advertised,
            client_window: self.control.send_window[Side::Client],
            server_window: self.control.send_window[Side::Server],
            streams: self.streams.admitted,
            frames: self.frames,
            issues: self.issues,
            pending_settings: pending.settings,
            pending_pings: pending.pings,
            upgrade_response: self.upgrade.response.take(),
            upgrade_sources: self.upgrade.sources.take(),
        });
        context.release_all(&mut self.upgrade.charge)?;
        Ok(())
    }
}
