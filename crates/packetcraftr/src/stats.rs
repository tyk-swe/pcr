// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_netio::capture::Statistics;
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
        let sum = Self {
            packets_attempted: self
                .packets_attempted
                .checked_add(value.packets_attempted)?,
            packets_completed: self
                .packets_completed
                .checked_add(value.packets_completed)?,
            bytes: self.bytes.checked_add(value.bytes)?,
            elapsed: self.elapsed.checked_add(value.elapsed)?,
            capture: self.capture.checked_add(value.capture)?,
        };
        *self = sum;
        Some(())
    }
}
