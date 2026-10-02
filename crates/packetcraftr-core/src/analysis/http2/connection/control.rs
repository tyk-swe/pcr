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
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: None,
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "unsolicited_settings_ack",
                        detail: "a SETTINGS acknowledgment does not match a pending SETTINGS"
                            .into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                return Ok(());
            };
            self.release_conn(cx, acked.charged);
            let mut overflow = false;
            for stream in self.streams.values_mut() {
                cx.check_deadline()?;
                if stream.phase != StreamPhase::Closed {
                    if acked
                        .peak_window_delta
                        .is_some_and(|peak| stream.send_window[side] + peak > settings::WINDOW_MAX)
                    {
                        overflow = true;
                    }
                    stream.send_window[side] += acked.window_delta;
                }
            }
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
            }
            if let Some(dir) = self.dirs[side].as_mut()
                && let Some(decoder) = dir.decoder.as_mut()
            {
                if let Some(minimum) = acked.minimum_table_size {
                    decoder.acknowledge_table_size(minimum)?;
                }
                decoder.acknowledge_table_size(acked.values.header_table_size)?;
                for pending in &self.settings[peer(side)].pending {
                    decoder.permit_table_size(pending.final_values.header_table_size);
                }
            }
            self.decoder_sync(side, cx)?;
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
        let applied = self.settings[side].apply(&settings, side == SERVER);
        let mut pending = applied.pending;
        pending.charged = resources::PENDING_OVERHEAD;
        self.charge_conn(cx, pending.charged)?;
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
            self.send_window[grant] += i64::from(increment);
            if self.send_window[grant] > settings::WINDOW_MAX {
                self.issue(
                    cx,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(0),
                        scope: IssueScope::Connection,
                        certainty: Certainty::Confirmed,
                        status: Status::Malformed,
                        code: "connection_window_overflow",
                        detail: "connection flow window exceeds 2^31-1".into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                self.fail(cx, Status::Malformed)?;
            }
            return Ok(());
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            if self.closed.contains_key(&stream_id) {
                return Ok(());
            }
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::ObservedOrder,
                    status: Status::Malformed,
                    code: "window_update_unknown_stream",
                    detail: "WINDOW_UPDATE on a stream that is not open".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            return Ok(());
        };
        if stream.phase == StreamPhase::Closed {
            return Ok(());
        }
        stream.send_window[grant] += i64::from(increment);
        if stream.send_window[grant] > settings::WINDOW_MAX {
            self.issue(
                cx,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "stream_window_overflow",
                    detail: "stream flow window exceeds 2^31-1".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
        }
        Ok(())
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
        }
        self.goaway[side] =
            Some(self.goaway[side].map_or(last_stream_id, |p| p.min(last_stream_id)));
        let scratch = self.streams.len() * size_of::<u32>();
        cx.charge_live(scratch)?;
        let result = (|| {
            let mut emitted = Vec::with_capacity(self.streams.len());
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
