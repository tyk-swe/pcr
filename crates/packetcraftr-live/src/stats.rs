// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_network::capture::Statistics;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: Statistics,
}

impl Stats {
    /// Accumulates `value` into these counters, or leaves them untouched and
    /// returns `None` if any single counter would overflow.
    pub fn checked_add(&mut self, value: &Self) -> Option<()> {
        let mut sum = self.clone();
        sum.packets_attempted = sum.packets_attempted.checked_add(value.packets_attempted)?;
        sum.packets_completed = sum.packets_completed.checked_add(value.packets_completed)?;
        sum.bytes = sum.bytes.checked_add(value.bytes)?;
        sum.elapsed = sum.elapsed.checked_add(value.elapsed)?;
        sum.capture.received_frames = sum
            .capture
            .received_frames
            .checked_add(value.capture.received_frames)?;
        sum.capture.received_bytes = sum
            .capture
            .received_bytes
            .checked_add(value.capture.received_bytes)?;
        sum.capture.dropped_frames = sum
            .capture
            .dropped_frames
            .checked_add(value.capture.dropped_frames)?;
        sum.capture.dropped_bytes = sum
            .capture
            .dropped_bytes
            .checked_add(value.capture.dropped_bytes)?;
        sum.capture.overflow_events = sum
            .capture
            .overflow_events
            .checked_add(value.capture.overflow_events)?;
        sum.capture.receiver_dropped_frames = sum
            .capture
            .receiver_dropped_frames
            .checked_add(value.capture.receiver_dropped_frames)?;
        *self = sum;
        Some(())
    }
}
