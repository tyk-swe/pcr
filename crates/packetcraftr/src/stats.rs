// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_netio::capture::Statistics;

/// A counter in [`Stats`] would exceed its range; the counters were left
/// untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("statistic accounting overflowed")]
pub struct StatsOverflow;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: Statistics,
}

impl Stats {
    /// Accumulates `value` into these counters, or leaves them untouched and
    /// reports [`StatsOverflow`] if any single counter would overflow.
    pub fn checked_add_assign(&mut self, value: &Self) -> Result<(), StatsOverflow> {
        let sum = Self {
            packets_attempted: self
                .packets_attempted
                .checked_add(value.packets_attempted)
                .ok_or(StatsOverflow)?,
            packets_completed: self
                .packets_completed
                .checked_add(value.packets_completed)
                .ok_or(StatsOverflow)?,
            bytes: self.bytes.checked_add(value.bytes).ok_or(StatsOverflow)?,
            elapsed: self
                .elapsed
                .checked_add(value.elapsed)
                .ok_or(StatsOverflow)?,
            capture: self
                .capture
                .checked_add(value.capture)
                .ok_or(StatsOverflow)?,
        };
        *self = sum;
        Ok(())
    }
}
