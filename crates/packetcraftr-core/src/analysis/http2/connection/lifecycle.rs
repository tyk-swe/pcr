// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, Connection, IssueScope, Startup, Status};
use super::super::stream::{CLIENT, SERVER};
use super::{Conn, Cx, DirPhase, Fault, Phase, resources};
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use bytes::Bytes;

impl Conn {
    pub(crate) fn close(
        &mut self,
        flow: &ScopedFlowKey,
        reset: bool,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if reset {
            return self.terminate(
                flow,
                Status::Reset,
                "connection_reset",
                "the TCP connection reset",
                cx,
            );
        }
        let mut faults = Vec::new();
        if let Some(dir) = self.dir_mut(flow) {
            dir.closed = true;
            let phase = dir.phase;
            let partial = dir.buffer.len();
            if partial > 0 {
                let sets = dir.buffer.contributors(partial);
                let (wire, dropped) = dir.buffer.take(partial);
                let sources = union_balanced(sets)?;
                Self::release_dir(dir, cx, partial);
                Self::release_dropped(dir, dropped, cx);
                let detail = match phase {
                    DirPhase::Sniff => "connection closed before startup was determined",
                    DirPhase::Prelude => "connection closed mid HTTP/1 exchange",
                    DirPhase::Preface => "connection closed inside the client preface",
                    DirPhase::Frames => "connection closed mid-frame",
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
                Self::release_dir(dir, cx, chain.charged);
                dir.charged_spans -= chain.charged_spans;
                *cx.spans = cx
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
            self.issue(cx, fault)?;
        }
        if let Some(side) = self.side_of(flow) {
            let ids: Vec<u32> = self
                .streams
                .iter()
                .filter(|(_, s)| s.msgs[side].is_some())
                .map(|(id, _)| *id)
                .collect();
            let flushed = !ids.is_empty();
            for id in ids {
                self.end_side(side, id, Status::Incomplete, cx)?;
            }
            if flushed {
                self.worst(Status::Incomplete);
            }
            self.maybe_done(cx);
        }
        Ok(())
    }

    fn maybe_done(&mut self, cx: &mut Cx<'_>) {
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
                cx.release_live(dir.charged);
                *cx.spans -= dir.charged_spans;
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
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if (self.done || matches!(self.phase, Phase::Dead)) && matches!(code, "tcp_evicted") {
            return Ok(());
        }
        self.issue(
            cx,
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
                Self::release_dir(dir, cx, partial);
                Self::release_dropped(dir, dropped, cx);
                partials.push((dir.flow.clone(), None, wire, sources));
            }
            if let Some(mut chain) = dir.chain.take() {
                Self::release_dir(dir, cx, chain.charged);
                dir.charged_spans -= chain.charged_spans;
                *cx.spans = cx
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
                cx,
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
        self.flush_messages(status, cx)?;
        self.fail(cx, status)
    }

    pub(crate) fn fail(&mut self, cx: &mut Cx<'_>, status: Status) -> Result<(), Error> {
        self.worst(status);
        self.phase = Phase::Dead;
        let mut faults = Vec::new();
        for dir in self.dirs.iter_mut().flatten() {
            if let Some(chain) = dir.chain.take() {
                Self::release_dir(dir, cx, chain.charged);
                dir.charged_spans = dir
                    .charged_spans
                    .checked_sub(chain.charged_spans)
                    .expect("chain spans");
                *cx.spans = cx
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
                cx,
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
        self.flush_messages(status, cx)?;
        Ok(())
    }

    pub(crate) fn flush_messages(
        &mut self,
        status: Status,
        cx: &mut Cx<'_>,
    ) -> Result<usize, Error> {
        let mut pending_msgs = Vec::new();
        for (id, stream) in self.streams.iter_mut() {
            for side in [CLIENT, SERVER] {
                if let Some(msg) = stream.msgs[side].take() {
                    pending_msgs.push((side, *id, msg));
                }
            }
            stream.phase = super::super::stream::Phase::Closed;
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
            self.release_conn(cx, msg.charged);
            *cx.spans = cx.spans.checked_sub(msg.charged_spans).expect("msg spans");
            self.issue(
                cx,
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
            self.release_conn(cx, msg.charged);
            *cx.spans = cx.spans.checked_sub(msg.charged_spans).expect("msg spans");
        }
        let emitted = pending_msgs.len();
        for (side, _, msg) in pending_msgs {
            self.emit_message(side, msg, status, cx)?;
        }
        Ok(emitted)
    }

    pub(crate) fn release_prelude(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
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
        self.release_conn(cx, release + charged);
        *cx.spans = cx.spans.checked_sub(spans).expect("prelude spans");
        Ok(())
    }

    pub(crate) fn finish(mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
        cx.check_deadline()?;
        for side in [CLIENT, SERVER] {
            if let Some(dir) = self.dirs[side].as_mut() {
                if !dir.buffer.is_empty() && !matches!(self.phase, Phase::Dead) {
                    let partial = dir.buffer.len();
                    let sets = dir.buffer.contributors(partial);
                    let (wire, dropped) = dir.buffer.take(partial);
                    let sources = union_balanced(sets)?;
                    Self::release_dir(dir, cx, partial);
                    Self::release_dropped(dir, dropped, cx);
                    let flow = dir.flow.clone();
                    self.issue(
                        cx,
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
                    && self.dirs[side]
                        .as_ref()
                        .is_some_and(|dir| dir.saw_frame || !dir.buffer.is_empty())
                {
                    self.issue(
                        cx,
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
                && (self
                    .dirs
                    .iter()
                    .any(|dir| dir.as_ref().is_none_or(|dir| dir.phase != DirPhase::Frames))
                    || self.settings.iter().any(|direction| !direction.seen)
                    || self
                        .streams
                        .values()
                        .any(|stream| stream.ended != [true, true]))
            {
                self.worst(Status::Incomplete);
            }
            if self.dirs[CLIENT].is_none() {
                let all_garbage =
                    !self.pending.is_empty() && self.pending.iter().all(|dir| dir.garbage);
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
                    cx,
                )?;
            }
            let flushed = self.flush_messages(Status::Incomplete, cx)?;
            if flushed > 0 {
                self.worst(Status::Incomplete);
            }
        }
        self.emit_connection(cx)?;
        self.drain(cx)?;
        Ok(())
    }

    pub(crate) fn emit_connection(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
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
        cx.charge_retained(charge)?;
        cx.summary.connections += 1;
        match self.startup {
            Startup::PriorKnowledge => cx.summary.prior_knowledge_connections += 1,
            Startup::H2c => cx.summary.upgraded_connections += 1,
            Startup::Unknown => cx.summary.unsupported_connections += 1,
        }
        cx.connection(Connection {
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
        self.release_conn(cx, upgrade_charge);
        Ok(())
    }
}
