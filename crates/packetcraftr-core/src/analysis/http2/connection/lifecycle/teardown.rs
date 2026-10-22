// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Partial-message flushing, final resource teardown, and connection publication.

use bytes::Bytes;

use crate::analysis::http2::Error;
use crate::analysis::http2::buffer::union_balanced;
use crate::analysis::http2::connection::{
    ConnectionState, Context, DirectionPhase, Fault, Phase, resources,
};
use crate::analysis::http2::model::{Certainty, Connection, IssueScope, Startup, Status};
use crate::analysis::http2::stream::{CLIENT, Phase as StreamPhase, SERVER};

impl ConnectionState {
    pub(crate) fn flush_messages(
        &mut self,
        status: Status,
        context: &mut Context<'_>,
    ) -> Result<usize, Error> {
        let mut pending_msgs = Vec::new();
        let promises = std::mem::take(&mut self.parent_deferred);
        self.release_conn(context, promises.len() * resources::PENDING_OVERHEAD);
        for msg in promises {
            pending_msgs.push((SERVER, msg.stream_id, msg));
        }
        let immediate = std::mem::take(&mut self.ack_deferred);
        self.release_conn(context, immediate.len() * resources::PENDING_OVERHEAD);
        for (side, msg, _) in immediate {
            pending_msgs.push((side, msg.stream_id, msg));
        }

        for (id, stream) in self.streams.iter_mut() {
            for side in [CLIENT, SERVER] {
                if let Some(msg) = stream.msgs[side].take() {
                    pending_msgs.push((side, *id, msg));
                }
            }
            stream.phase = StreamPhase::Closed;
        }
        let mut upgrade_evidence = Vec::new();
        let mut release = Vec::new();
        if let Some(prelude) = self.prelude.as_mut() {
            if let Some(mut msg) = prelude.live_request.take() {
                if prelude.offers.contains_key(&msg.index) {
                    if prelude.upgraded {
                        msg.stream_id = 1;
                        pending_msgs.push((CLIENT, 1, msg));
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
                        pending_msgs.push((CLIENT, 1, msg));
                    } else {
                        upgrade_evidence.push(msg);
                    }
                }
            }
        }
        for mut msg in upgrade_evidence {
            let head = msg.upgrade_head.take().expect("upgrade request head");
            let sources = union_balanced(std::mem::take(&mut msg.sets))?;
            self.release_conn(context, msg.charged);
            *context.spans = context
                .spans
                .checked_sub(msg.charged_spans)
                .expect("msg spans");
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(CLIENT),
                    http2_stream_id: None,
                    scope: IssueScope::Capture,
                    certainty: Certainty::Confirmed,
                    status,
                    code: "incomplete_upgrade",
                    detail: "the byte stream ended before the h2c upgrade completed".into(),
                    wire: head.wire().clone(),
                    sources,
                },
            )?;
        }
        for msg in release {
            self.release_conn(context, msg.charged);
            *context.spans = context
                .spans
                .checked_sub(msg.charged_spans)
                .expect("msg spans");
        }
        let emitted = pending_msgs.len();
        for (side, _, msg) in pending_msgs {
            self.emit_message(side, msg, status, context)?;
        }
        Ok(emitted)
    }

    pub(crate) fn release_prelude(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Some(prelude) = self.prelude.take() else {
            return Ok(());
        };
        let mut release = prelude.requests.len() * resources::PENDING_OVERHEAD;
        release += prelude
            .offers
            .values()
            .map(|offer| resources::OFFER_OVERHEAD + offer.settings.capacity() * 24)
            .sum::<usize>();
        release += resources::DIR_OVERHEAD;
        release += prelude.body_charge.iter().sum::<usize>();
        let mut charged = 0usize;
        let mut spans = 0usize;
        for msg in [prelude.live_request, prelude.live_response]
            .into_iter()
            .flatten()
            .chain(prelude.offers.into_values().filter_map(|o| o.msg))
        {
            charged += msg.charged;
            spans += msg.charged_spans;
        }
        self.release_conn(context, release + charged);
        *context.spans = context.spans.checked_sub(spans).expect("prelude spans");
        Ok(())
    }

    pub(crate) fn finish(mut self, context: &mut Context<'_>) -> Result<(), Error> {
        context.check_deadline()?;
        self.finalizing = true;
        if self.phase == Phase::H2 {
            self.pump(context)?;
        }
        self.report_unmatched_response_at_eof(context)?;
        for side in [CLIENT, SERVER] {
            if let Some(dir) = self.dirs[side].as_mut() {
                if !dir.buffer.is_empty() && !matches!(self.phase, Phase::Dead) {
                    let partial = dir.buffer.len();
                    let sets = dir.buffer.contributors(partial);
                    let (wire, dropped) = dir.buffer.take(partial);
                    let sources = union_balanced(sets)?;
                    Self::release_dir(dir, context, partial);
                    Self::release_dropped(dir, dropped, context);
                    let flow = dir.flow.clone();
                    self.issue(
                        context,
                        Fault {
                            flow,
                            http2_stream_id: None,
                            scope: IssueScope::Capture,
                            certainty: Certainty::Confirmed,
                            status: Status::Incomplete,
                            code: "unconsumed_bytes",
                            detail: "the capture ended with undecoded bytes".into(),
                            wire,
                            sources,
                        },
                    )?;
                }
                if !self.settings[side].seen
                    && self.dirs[side].as_ref().is_some_and(|dir| {
                        self.clean_start || dir.saw_frame || !dir.buffer.is_empty()
                    })
                {
                    self.issue(
                        context,
                        Fault {
                            flow: self.dir_flow(side),
                            http2_stream_id: None,
                            scope: IssueScope::Connection,
                            certainty: if self.clean_start {
                                Certainty::Confirmed
                            } else {
                                Certainty::Indeterminate
                            },
                            status: Status::Incomplete,
                            code: "settings_unobserved",
                            detail: "the endpoint's initial SETTINGS were never observed".into(),
                            wire: Bytes::new(),
                            sources: None,
                        },
                    )?;
                }
            }
        }
        if !matches!(self.phase, Phase::Dead) {
            if matches!(self.phase, Phase::H2)
                && (self.dirs.iter().any(|dir| {
                    dir.as_ref()
                        .is_none_or(|dir| dir.phase != DirectionPhase::Frames)
                }) || self.settings.iter().any(|direction| !direction.seen)
                    || self
                        .streams
                        .values()
                        .any(|stream| stream.ended != [true, true]))
            {
                self.worst(Status::Incomplete);
            }
            if self.dirs[CLIENT].is_none() {
                let all_garbage = self.pending.iter().any(|dir| dir.received)
                    && self.pending.iter().all(|dir| !dir.received || dir.garbage);
                self.worst(if self.startup == Startup::Unknown && all_garbage {
                    Status::Unsupported
                } else {
                    Status::Incomplete
                });
            } else if matches!(self.phase, Phase::Prelude | Phase::Sniff) {
                self.worst(
                    if self.refused
                        || (self.done
                            && self
                                .prelude
                                .as_ref()
                                .is_none_or(|prelude| prelude.offers.is_empty()))
                    {
                        Status::Unsupported
                    } else {
                        Status::Incomplete
                    },
                );
            } else if self.prelude.is_some() && !self.refused {
                self.worst(Status::Incomplete);
            } else if self.refused {
                self.worst(Status::Unsupported);
            } else if self.dirs[SERVER].is_none() && self.frames > 0 {
                self.worst(Status::Incomplete);
            }
            if !self.done {
                let flow = self.flow();
                self.terminate(
                    &flow,
                    Status::Incomplete,
                    "capture_end",
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
        let charge = resources::EVENT_OVERHEAD
            + resources::MESSAGE_OVERHEAD
            + self
                .upgrade_response
                .as_ref()
                .map_or(0, |head| head.wire().len())
            + self.upgrade_sources.as_ref().map_or(0, |set| {
                resources::SET_OVERHEAD + set.frames().len() * resources::SPAN_OVERHEAD
            });
        context.charge_retained(charge)?;
        context.summary.connections += 1;
        match self.startup {
            Startup::PriorKnowledge => context.summary.prior_knowledge_connections += 1,
            Startup::H2c => context.summary.upgraded_connections += 1,
            Startup::Unknown => context.summary.unsupported_connections += 1,
        }
        context.connection(Connection {
            stream: self.stream,
            generation: self.generation,
            flow: self.flow(),
            startup: self.startup,
            status: self.status,
            client_settings: self.settings[CLIENT].advertised,
            server_settings: self.settings[SERVER].advertised,
            client_window: self.send_window[CLIENT],
            server_window: self.send_window[SERVER],
            streams: self.admitted_streams,
            frames: self.frames,
            issues: self.issues,
            pending_settings: self.final_pending_settings.unwrap_or_else(|| {
                (self.settings[CLIENT].pending.len() + self.settings[SERVER].pending.len()) as u64
            }),
            pending_pings: self.final_pending_pings.unwrap_or_else(|| {
                self.pings
                    .iter()
                    .map(|pings| pings.values().sum::<u64>())
                    .sum()
            }),
            upgrade_response: self.upgrade_response.take(),
            upgrade_sources: self.upgrade_sources.take(),
        });
        let upgrade_charge = std::mem::take(&mut self.upgrade_charge);
        self.release_conn(context, upgrade_charge);
        Ok(())
    }
}
