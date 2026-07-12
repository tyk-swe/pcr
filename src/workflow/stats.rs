// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::net::capture::Statistics as CaptureStatistics;

/// Packet, byte, elapsed-time, and capture counters shared by live workflows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

impl Stats {
    pub(super) fn from_client(stats: crate::client::Stats) -> Self {
        Self {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture,
        }
    }

    pub(super) fn checked_add(&mut self, value: &Self) -> Option<()> {
        self.packets_attempted = self
            .packets_attempted
            .checked_add(value.packets_attempted)?;
        self.packets_completed = self
            .packets_completed
            .checked_add(value.packets_completed)?;
        self.bytes = self.bytes.checked_add(value.bytes)?;
        self.elapsed = self.elapsed.checked_add(value.elapsed)?;
        self.capture.received_frames = self
            .capture
            .received_frames
            .checked_add(value.capture.received_frames)?;
        self.capture.received_bytes = self
            .capture
            .received_bytes
            .checked_add(value.capture.received_bytes)?;
        self.capture.dropped_frames = self
            .capture
            .dropped_frames
            .checked_add(value.capture.dropped_frames)?;
        self.capture.dropped_bytes = self
            .capture
            .dropped_bytes
            .checked_add(value.capture.dropped_bytes)?;
        self.capture.overflow_events = self
            .capture
            .overflow_events
            .checked_add(value.capture.overflow_events)?;
        self.capture.receiver_dropped_frames = self
            .capture
            .receiver_dropped_frames
            .checked_add(value.capture.receiver_dropped_frames)?;
        Some(())
    }
}
