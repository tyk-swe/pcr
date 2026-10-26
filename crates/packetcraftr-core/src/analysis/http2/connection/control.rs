// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection control frames, with SETTINGS and flow control in child modules.

mod flow_control;
mod settings;

use super::super::Error;
use super::super::model::{Certainty, IssueScope, Status};
use super::{ConnectionState, Context, Evidence, Fault};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http2 as wire;

impl ConnectionState {
    pub(crate) fn goaway_frame(
        &mut self,
        side: Side,
        last_stream_id: u32,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if let Some(previous) = self.goaway[side]
            && last_stream_id > previous
        {
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: IssueCode::GoawayLastStreamIncreased,
                    detail: "GOAWAY last_stream_id must not increase".into(),
                    wire: evidence.wire.clone(),
                    sources: evidence.sources.clone(),
                },
            )?;
            self.fail(context, Status::Malformed)?;
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
            context.check_deadline()?;
            capacity += 1;
        }
        let scratch = capacity * size_of::<u32>();
        context.reserve_scratch(scratch)?;
        let result = self.goaway_unprocessed(
            side,
            last_stream_id,
            capacity,
            closed_range,
            &evidence,
            context,
        );
        context.release_scratch(scratch)?;
        result
    }

    fn goaway_unprocessed(
        &mut self,
        side: Side,
        last_stream_id: u32,
        capacity: usize,
        closed_range: (std::ops::Bound<u32>, std::ops::Bound<u32>),
        evidence: &Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let mut emitted = Vec::with_capacity(capacity);
        for (id, stream) in &mut self.streams {
            context.check_deadline()?;
            let initiated_by_receiver = stream.initiator == side.peer();
            if *id > last_stream_id && initiated_by_receiver {
                if !stream.unprocessed && stream.ended[side.peer()] {
                    emitted.push(*id);
                }
                stream.unprocessed = true;
            }
        }
        for (id, _) in self.closed.range(closed_range) {
            context.check_deadline()?;
            if Side::initiator_of(*id) == side.peer() {
                emitted.push(*id);
            }
        }
        for id in emitted {
            self.issue(context, Fault {
                flow: self.dir_flow(side),
                http2_stream_id: Some(id),
                scope: IssueScope::Stream,
                certainty: Certainty::Confirmed,
                status: Status::Unprocessed,
                code: IssueCode::GoawayUnprocessed,
                detail: "GOAWAY excludes this already-emitted request; the earlier event records byte completeness only".into(),
                wire: evidence.wire.clone(),
                sources: evidence.sources.clone(),
            })?;
        }
        Ok(())
    }
}

impl ConnectionState {
    pub(crate) fn ping_frame(
        &mut self,
        side: Side,
        flags: u8,
        opaque: [u8; 8],
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        const PING_ENTRY: usize = 64;
        if flags & wire::FLAG_ACK != 0 {
            let pending = &mut self.pings[side.peer()];
            match pending.get_mut(&opaque) {
                Some(count) => {
                    *count -= 1;
                    if *count == 0 {
                        pending.remove(&opaque);
                        context.release(&mut self.charge, PING_ENTRY)?;
                    }
                }
                None => {
                    self.issue(
                        context,
                        Fault {
                            flow: self.dir_flow(side),
                            http2_stream_id: None,
                            scope: IssueScope::Connection,
                            certainty: Certainty::ObservedOrder,
                            status: Status::Incomplete,
                            code: IssueCode::UnmatchedPingAck,
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
        context.charge(&mut self.charge, PING_ENTRY)?;
        self.pings[side].insert(opaque, 1);
        Ok(())
    }
}
