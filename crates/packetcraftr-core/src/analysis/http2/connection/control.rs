// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::model::{Certainty, IssueScope, Status};
use super::super::stream::{Phase as StreamPhase, SERVER, peer};
use super::super::{Error, settings};
use super::{Conn, Cx, Evidence, Fault, resources};
use crate::protocol::application::http2 as wire;

impl Conn {
    pub(crate) fn settings_frame(
        &mut self,
        side: usize,
        flags: u8,
        settings: Vec<wire::Setting>,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if flags & 0x1 != 0 {
            let Some(acked) = self.settings[super::super::stream::peer(side)].acknowledge() else {
                // Two unmatched ACK heads cannot be explained by reordering:
                // both matching SETTINGS would have to precede the other's ACK.
                // Retain the peer's still-buffered evidence before failure drains it.
                let peer_ack = self.dirs[peer(side)]
                    .as_ref()
                    .filter(|dir| {
                        let bytes = dir.buffer.bytes();
                        self.settings[side].pending.is_empty()
                            && dir.saw_frame
                            && dir.chain.is_none()
                            && bytes.len() >= 9
                            && bytes[..3] == [0, 0, 0]
                            && bytes[3] == 4
                            && bytes[4] & 1 != 0
                            && bytes[5] & 0x7f == 0
                            && bytes[6..9] == [0, 0, 0]
                    })
                    .map(|dir| {
                        (
                            bytes::Bytes::copy_from_slice(&dir.buffer.bytes()[..9]),
                            dir.buffer.contributors(9),
                        )
                    });
                let confirmed = self.clean_start
                    && (peer_ack.is_some()
                        || self.dirs[peer(side)]
                            .as_ref()
                            .is_some_and(|dir| dir.buffer.is_empty()));
                let status = if confirmed {
                    Status::Malformed
                } else {
                    Status::Incomplete
                };
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: if confirmed {
                            Certainty::Confirmed
                        } else {
                            Certainty::Indeterminate
                        },
                        status,
                        code: "unsolicited_settings_ack",
                        detail: "a SETTINGS acknowledgment does not match a pending SETTINGS"
                            .into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                if let Some((wire, sets)) = peer_ack {
                    self.issue(
                        cx,
                        Fault {
                            flow: self.dir_flow(peer(side)),
                            http2_stream_id: None,
                            scope: IssueScope::Connection,
                            certainty: if confirmed {
                                Certainty::Confirmed
                            } else {
                                Certainty::Indeterminate
                            },
                            status,
                            code: "unsolicited_settings_ack",
                            detail: "both directional ACK heads lack preceding matching SETTINGS"
                                .into(),
                            wire,
                            sources: super::super::buffer::union_balanced(sets)?,
                        },
                    )?;
                }
                self.fail(cx, status)?;
                return Ok(());
            };
            let mut overflow = false;
            for (id, stream) in &mut self.streams {
                cx.check_deadline()?;
                if stream.phase != StreamPhase::Closed {
                    let owner = if stream.by_client {
                        super::super::stream::CLIENT
                    } else {
                        SERVER
                    };
                    let existed = owner != peer(side) || *id <= acked.sender_stream_limit;
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
            self.release_conn(cx, acked.charged);
            for debt in self.closed_credit.values_mut() {
                cx.check_deadline()?;
                if let Some(window) = debt[side].as_mut() {
                    *window += acked.window_delta;
                    if *window >= 0 {
                        debt[side] = None;
                    }
                }
            }
            self.release_resolved_credit(cx);
            if overflow {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "window_overflow",
                        detail: "SETTINGS window change pushed a stream window out of range".into(),
                        wire: evidence.wire.clone(),
                        sources: evidence.sources.clone(),
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
                return Ok(());
            }
            if let Some(dir) = self.dirs[side].as_mut()
                && let Some(decoder) = dir.decoder.as_mut()
            {
                if let Some(minimum) = acked.minimum_table_size {
                    if acked.possibly_applied_table_minimum {
                        let uncertain = &mut self.settings[peer(side)].uncertain_table_minimum;
                        *uncertain = Some(uncertain.map_or(minimum, |old| old.min(minimum)));
                    } else {
                        decoder.acknowledge_table_size(minimum)?;
                    }
                }
                decoder.acknowledge_table_size(acked.values.header_table_size)?;
                for pending in &self.settings[peer(side)].pending {
                    decoder.permit_table_size(pending.final_values.header_table_size);
                }
            }
            self.decoder_sync(side, cx)?;
            self.reconcile_closed_credit(side, None, cx)?;
            self.release_ack_deferred_messages(cx)?;
            return Ok(());
        }
        if self.settings[side].pending.len() + 1 > cx.limits.max_pending_settings {
            let flow = self.dir_flow(side);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Limit,
                    code: "pending_settings",
                    detail: "unacknowledged SETTINGS frames exceed the configured bound".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            self.fail(cx, Status::Limit)?;
            return Ok(());
        }
        let resume_peer = self.waiting_settings_ack(peer(side));
        let applied = self.settings[side].apply(&settings, side == SERVER);
        let mut pending = applied.pending;
        pending.sender_stream_limit = self.max_initiated[side];
        pending.charged = resources::PENDING_OVERHEAD
            + self
                .streams
                .len()
                .saturating_mul(resources::CLOSED_STREAM_OVERHEAD);
        self.charge_conn(cx, pending.charged)?;
        for (id, stream) in &self.streams {
            cx.check_deadline()?;
            pending
                .window_grants
                .insert(*id, stream.window_granted[peer(side)]);
        }
        let advertised_table_size = pending.final_values.header_table_size;
        self.settings[side].pending.push_back(pending);
        if let Some(decoder) = self.dirs[peer(side)]
            .as_mut()
            .and_then(|dir| dir.decoder.as_mut())
        {
            decoder.permit_table_size(advertised_table_size);
        }
        let issues = applied.issues;
        let invalid = !issues.is_empty();
        for issue in issues {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: issue.code,
                    detail: issue.detail.into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
        }
        if invalid {
            self.fail(cx, Status::Malformed)?;
        } else if resume_peer {
            self.resume_side = Some(peer(side));
        }
        Ok(())
    }

    pub(crate) fn window_update(
        &mut self,
        side: usize,
        stream_id: u32,
        increment: u32,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let grant = peer(side);
        if stream_id == 0 {
            self.send_window[grant] = self.send_window[grant].saturating_add(i64::from(increment));
            if self.send_window[grant] > settings::WINDOW_MAX {
                let confirmed = self.dirs[grant]
                    .as_ref()
                    .is_some_and(|dir| dir.closed && dir.buffer.is_empty());
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(0),
                        scope: IssueScope::Connection,
                        certainty: if confirmed {
                            Certainty::Confirmed
                        } else {
                            Certainty::ObservedOrder
                        },
                        status: if confirmed {
                            Status::Malformed
                        } else {
                            Status::Incomplete
                        },
                        code: "connection_window_overflow",
                        detail: "connection flow window exceeds 2^31-1".into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                if confirmed {
                    self.fail(cx, Status::Malformed)?;
                }
            }
            return Ok(());
        }
        if let Some(debt) = self.closed_credit.get_mut(&stream_id) {
            if let Some(window) = debt[grant].as_mut() {
                *window = window.saturating_add(i64::from(increment));
                if *window >= 0 {
                    debt[grant] = None;
                }
            }
            self.release_credit(stream_id, cx);
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            let owner = if stream_id.is_multiple_of(2) {
                SERVER
            } else {
                super::super::stream::CLIENT
            };
            if self.closed.contains_key(&stream_id) || stream_id <= self.max_initiated[owner] {
                return Ok(());
            }
            let confirmed_idle = self.clean_start && side == owner;
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: if confirmed_idle {
                        Certainty::Confirmed
                    } else {
                        Certainty::ObservedOrder
                    },
                    status: Status::Malformed,
                    code: "window_update_unknown_stream",
                    detail: "WINDOW_UPDATE on a stream that is not open".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if confirmed_idle {
                self.fail(cx, Status::Malformed)?;
            }
            return Ok(());
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
        if stream.send_window[grant] > settings::WINDOW_MAX {
            let confirmed = stream.ended[grant];
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: if confirmed {
                        Certainty::Confirmed
                    } else {
                        Certainty::ObservedOrder
                    },
                    status: if confirmed {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    code: "stream_window_overflow",
                    detail: "stream flow window exceeds 2^31-1".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if confirmed {
                self.close_stream(stream_id, Status::Malformed, None, cx)?;
            }
        }
        Ok(())
    }

    /// A clean, fully consumed granting direction cannot hide later credit.
    pub(crate) fn reconcile_closed_credit(
        &mut self,
        side: usize,
        only_stream: Option<u32>,
        cx: &mut Cx<'_>,
    ) -> Result<bool, Error> {
        if self.phase != super::Phase::H2
            || !self.clean_start
            || !self.dirs[peer(side)]
                .as_ref()
                .is_some_and(|dir| dir.closed && dir.buffer.is_empty() && dir.chain.is_none())
        {
            return Ok(false);
        }
        if self.send_window[side] < 0 {
            self.issue(cx, Fault {
                flow: self.dir_flow(side), http2_stream_id: Some(0),
                scope: IssueScope::Connection, certainty: Certainty::Confirmed,
                status: Status::Malformed, code: "connection_window_exceeded",
                detail: "DATA exhausted connection credit after the granting direction ended; prior DATA evidence is retained".into(),
                wire: bytes::Bytes::new(), sources: None,
            })?;
            self.fail(cx, Status::Malformed)?;
            return Ok(true);
        }
        // A not-yet-ACKed SETTINGS increase may already have supplied credit.
        let mut delta = 0i64;
        let mut extra = 0i64;
        for pending in &self.settings[peer(side)].pending {
            cx.check_deadline()?;
            delta += pending.window_delta;
            extra = extra.max(delta);
        }
        let mut cursor = 0;
        loop {
            cx.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self
                    .streams
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(id, _)| *id),
            };
            let Some(id) = id else {
                break;
            };
            cursor = id;
            if self.streams.get(&id).is_some_and(|stream| {
                stream.credit_exceeded[side] && stream.send_window[side] + extra < 0
            }) {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "stream_window_exceeded",
                    detail: "DATA exhausted stream credit after the granting direction ended; prior DATA evidence is retained".into(),
                    wire: bytes::Bytes::new(), sources: None,
                })?;
                self.streams.get_mut(&id).expect("stream").credit_exceeded[side] = false;
                self.close_stream(id, Status::Malformed, None, cx)?;
                if only_stream.is_some() {
                    return Ok(true);
                }
            }
        }
        let mut cursor = 0;
        loop {
            cx.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self
                    .closed_credit
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(id, _)| *id),
            };
            let Some(id) = id else {
                break;
            };
            cursor = id;
            if self
                .closed_credit
                .get(&id)
                .and_then(|debt| debt[side])
                .is_some_and(|window| window + extra < 0)
            {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "stream_window_exceeded",
                    detail: "completed stream DATA exhausted credit before the granting direction ended; earlier DATA evidence is retained".into(),
                    wire: bytes::Bytes::new(), sources: None,
                })?;
                self.closed_credit.get_mut(&id).expect("debt")[side] = None;
                self.release_credit(id, cx);
            }
        }
        Ok(false)
    }

    pub(crate) fn retain_closed_credit(&mut self, id: u32, cx: &mut Cx<'_>) -> Result<(), Error> {
        let stream = self.streams.get(&id).expect("stream");
        let debt = std::array::from_fn(|side| {
            (stream.credit_exceeded[side] && stream.send_window[side] < 0)
                .then_some(stream.send_window[side])
        });
        if debt.iter().any(Option::is_some) && !self.closed_credit.contains_key(&id) {
            self.charge_conn(cx, resources::CLOSED_CREDIT_OVERHEAD)?;
            self.closed_credit.insert(id, debt);
        }
        Ok(())
    }

    fn release_credit(&mut self, id: u32, cx: &mut Cx<'_>) {
        if self
            .closed_credit
            .get(&id)
            .is_some_and(|debt| debt.iter().all(Option::is_none))
        {
            self.closed_credit.remove(&id);
            self.release_conn(cx, resources::CLOSED_CREDIT_OVERHEAD);
        }
    }

    fn release_resolved_credit(&mut self, cx: &mut Cx<'_>) {
        let before = self.closed_credit.len();
        self.closed_credit
            .retain(|_, debt| debt.iter().any(Option::is_some));
        self.release_conn(
            cx,
            (before - self.closed_credit.len()) * resources::CLOSED_CREDIT_OVERHEAD,
        );
    }

    pub(crate) fn goaway_frame(
        &mut self,
        side: usize,
        last_stream_id: u32,
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        if let Some(previous) = self.goaway[side]
            && last_stream_id > previous
        {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "goaway_last_stream_increased",
                    detail: "GOAWAY last_stream_id must not increase".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(());
        }
        let previous_last = self.goaway[side];
        let effective_last = previous_last.map_or(last_stream_id, |p| p.min(last_stream_id));
        self.goaway[side] = Some(effective_last);
        let closed_range = (
            std::ops::Bound::Excluded(effective_last),
            previous_last.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Included),
        );
        // Successive GOAWAY bounds only decrease: scan newly excluded closed
        // IDs, rather than revisiting every completed stream for every frame.
        let mut capacity = self.streams.len();
        for _ in self.closed.range(closed_range) {
            cx.check_deadline()?;
            capacity += 1;
        }
        let scratch = capacity * size_of::<u32>();
        cx.charge_live(scratch)?;
        let result = (|| {
            let mut emitted = Vec::with_capacity(capacity);
            for (id, stream) in &mut self.streams {
                cx.check_deadline()?;
                let initiated_by_receiver = stream.by_client == (side == SERVER);
                if *id > last_stream_id && initiated_by_receiver {
                    if !stream.unprocessed && stream.ended[peer(side)] {
                        emitted.push(*id);
                    }
                    stream.unprocessed = true;
                }
            }
            for (id, _) in self.closed.range(closed_range) {
                cx.check_deadline()?;
                let initiated_by_receiver = !id.is_multiple_of(2) == (side == SERVER);
                if initiated_by_receiver {
                    emitted.push(*id);
                }
            }
            for id in emitted {
                self.issue(cx, Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Unprocessed,
                    code: "goaway_unprocessed",
                    detail: "GOAWAY excludes this already-emitted request; the earlier event records byte completeness only".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                })?;
            }
            Ok(())
        })();
        cx.release_live(scratch);
        result
    }
}

impl Conn {
    pub(crate) fn ping_frame(
        &mut self,
        side: usize,
        flags: u8,
        opaque: [u8; 8],
        evidence: Evidence,
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        const PING_ENTRY: usize = 64;
        if flags & 0x1 != 0 {
            let pending = &mut self.pings[peer(side)];
            match pending.get_mut(&opaque) {
                Some(count) => {
                    *count -= 1;
                    if *count == 0 {
                        pending.remove(&opaque);
                        self.release_conn(cx, PING_ENTRY);
                    }
                }
                None => {
                    self.issue(
                        cx,
                        Fault {
                            flow: self.dir_flow(side),
                            http2_stream_id: None,
                            scope: IssueScope::Connection,
                            certainty: Certainty::ObservedOrder,
                            status: Status::Incomplete,
                            code: "unmatched_ping_ack",
                            detail: "a PING acknowledgment carries an opaque value never observed"
                                .into(),
                            wire: evidence.wire,
                            sources: evidence.sources,
                        },
                    )?;
                }
            }
            return Ok(());
        }
        if let Some(count) = self.pings[side].get_mut(&opaque) {
            *count += 1;
            return Ok(());
        }
        self.charge_conn(cx, PING_ENTRY)?;
        self.pings[side].insert(opaque, 1);
        Ok(())
    }
}
