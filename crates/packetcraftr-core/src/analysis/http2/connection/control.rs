// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection control state (SETTINGS, windows, GOAWAY, PING) and handlers.

mod flow_control;
mod settings;

use super::super::Error;
use super::super::budget::{self, Charge};
use super::super::model::{Certainty, Status};
use super::super::settings::DirectionSettings;
use super::{ActiveState, Context, Evidence, Fault, Reporter, StepResult};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::{PerSide, Side};
use crate::protocol::application::http2 as wire;
use std::collections::BTreeMap;
use std::ops::Bound;

#[derive(Clone, Copy, Default)]
pub(crate) struct PendingCounts {
    pub settings: u64,
    pub pings: u64,
}

pub(crate) struct ControlState {
    pub settings: PerSide<DirectionSettings>,
    pub send_window: PerSide<i64>,
    pub goaway: PerSide<Option<u32>>,
    pub pings: PerSide<BTreeMap<[u8; 8], u64>>,
    pings_charge: Charge,
}

impl ControlState {
    pub(crate) fn new() -> Self {
        Self {
            settings: PerSide::new(DirectionSettings::new(), DirectionSettings::new()),
            send_window: PerSide::new(65_535, 65_535),
            goaway: PerSide::new(None, None),
            pings: PerSide::default(),
            pings_charge: Charge::default(),
        }
    }

    pub(crate) fn initial_windows(&self) -> PerSide<i64> {
        PerSide::new(
            i64::from(self.settings[Side::Server].acknowledged.initial_window_size),
            i64::from(self.settings[Side::Client].acknowledged.initial_window_size),
        )
    }

    pub(crate) fn pending_counts(&self) -> PendingCounts {
        PendingCounts {
            settings: self
                .settings
                .iter()
                .map(|direction| direction.pending.len() as u64)
                .sum(),
            pings: self
                .pings
                .iter()
                .map(|pings| pings.values().sum::<u64>())
                .sum(),
        }
    }

    pub(crate) fn release_all(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<PendingCounts, Error> {
        let counts = self.pending_counts();
        for direction in self.settings.iter_mut() {
            for mut pending in std::mem::take(&mut direction.pending) {
                context.release_all(&mut pending.charge)?;
            }
        }
        for pings in self.pings.iter_mut() {
            pings.clear();
        }
        context.release_all(&mut self.pings_charge)?;
        Ok(counts)
    }
}

struct GoawayScan<'a> {
    side: Side,
    last_stream_id: u32,
    capacity: usize,
    closed_range: (Bound<u32>, Bound<u32>),
    evidence: &'a Evidence,
}

impl ActiveState {
    pub(crate) fn goaway_frame(
        &mut self,
        side: Side,
        last_stream_id: u32,
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        if let Some(previous) = self.control.goaway[side]
            && last_stream_id > previous
        {
            return reporter.reject(
                context,
                Fault::connection(
                    self.directions.flow(side),
                    Status::Malformed,
                    IssueCode::GoawayLastStreamIncreased,
                    "GOAWAY last_stream_id must not increase",
                )
                .with_evidence(evidence.wire, evidence.sources),
            );
        }
        let previous_last = self.control.goaway[side];
        let effective_last = previous_last.map_or(last_stream_id, |prev| prev.min(last_stream_id));
        self.control.goaway[side] = Some(effective_last);
        let closed_range = (
            Bound::Excluded(effective_last),
            previous_last.map_or(Bound::Unbounded, Bound::Included),
        );
        // Successive GOAWAY bounds only decrease: scan newly excluded closed
        // IDs, rather than revisiting every completed stream for every frame.
        let mut capacity = self.streams.open_len();
        for _ in self.streams.closed_range(closed_range) {
            context.check_deadline()?;
            capacity += 1;
        }
        let scratch = capacity * size_of::<u32>();
        let scan = GoawayScan {
            side,
            last_stream_id,
            capacity,
            closed_range,
            evidence: &evidence,
        };
        context.with_scratch(scratch, |context| {
            self.mark_goaway_unprocessed(scan, reporter, context)
        })?;
        Ok(())
    }

    fn mark_goaway_unprocessed(
        &mut self,
        scan: GoawayScan<'_>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let GoawayScan {
            side,
            last_stream_id,
            capacity,
            closed_range,
            evidence,
        } = scan;
        let mut emitted = Vec::with_capacity(capacity);
        let peer = side.peer();
        for (id, stream) in self.streams.open_iter_mut() {
            context.check_deadline()?;
            if id > last_stream_id && stream.initiator == peer {
                if !stream.unprocessed && stream.ended[peer] {
                    emitted.push(id);
                }
                stream.unprocessed = true;
            }
        }
        for id in self.streams.closed_range(closed_range) {
            context.check_deadline()?;
            if Side::initiator_of(id) == peer {
                emitted.push(id);
            }
        }
        let flow = self.directions.flow(side);
        for id in emitted {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    id,
                    Status::Unprocessed,
                    IssueCode::GoawayUnprocessed,
                    "GOAWAY excludes this already-emitted request; the earlier event records byte completeness only",
                )
                .with_evidence_ref(evidence),
            )?;
        }
        Ok(())
    }

    pub(crate) fn ping_frame(
        &mut self,
        side: Side,
        flags: u8,
        opaque: [u8; 8],
        evidence: Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if flags & wire::FLAG_ACK != 0 {
            let pending = &mut self.control.pings[side.peer()];
            match pending.get_mut(&opaque) {
                Some(count) => {
                    *count -= 1;
                    if *count == 0 {
                        pending.remove(&opaque);
                        context
                            .release(&mut self.control.pings_charge, budget::PING_ENTRY_OVERHEAD)?;
                    }
                }
                None => {
                    reporter.issue(
                        context,
                        Fault::connection(
                            self.directions.flow(side),
                            Status::Incomplete,
                            IssueCode::UnmatchedPingAck,
                            "a PING acknowledgment carries an opaque value never observed",
                        )
                        .with_certainty(Certainty::ObservedOrder)
                        .with_evidence(evidence.wire, evidence.sources),
                    )?;
                }
            }
            return Ok(());
        }
        if let Some(count) = self.control.pings[side].get_mut(&opaque) {
            *count += 1;
            return Ok(());
        }
        context.charge(&mut self.control.pings_charge, budget::PING_ENTRY_OVERHEAD)?;
        self.control.pings[side].insert(opaque, 1);
        Ok(())
    }
}
