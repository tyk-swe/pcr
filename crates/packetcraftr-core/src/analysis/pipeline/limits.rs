// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Analysis limits and options.

use std::time::Duration;

use crate::analysis::pcap::{DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES};
use crate::filter::Filter;

use crate::analysis::Error;

const DEFAULT_MAX_ANALYSIS_FLOWS: usize = 8_192;

/// Finite resource ceilings for one analysis run.
///
/// The frame and byte budgets count every frame the capture yields, matched
/// or not, so a display filter can never raise how much input one run reads.
/// The duration budget bounds the run's own processing time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_flows: usize,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_flows: DEFAULT_MAX_ANALYSIS_FLOWS,
            max_duration: Duration::from_secs(3_600),
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
            ("max_flows", self.max_flows as u64),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(Error::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() {
            return Err(Error::InvalidLimit {
                field: "max_duration",
                value: 0,
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// What one analysis run computes beyond dispatching matched frames.
#[derive(Clone, Debug, Default)]
pub struct Options<'a> {
    /// Keeps only matching frames; compiled by the caller so filter mistakes
    /// surface before any input is read. Conversation indices are assigned
    /// before the filter runs, so `tcp.stream` and `udp.stream` resolve.
    pub filter: Option<&'a Filter>,
    /// Drives bounded TCP reassembly over the matched frames and delivers
    /// its events with each record. Costs memory proportional to reordering,
    /// so commands that only count leave it off.
    pub tcp_events: bool,
    pub limits: Limits,
}
