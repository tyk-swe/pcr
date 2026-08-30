// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Analysis limits and options.

use std::time::{Duration, Instant};

use crate::analysis::pcap::{DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES};
use crate::analysis::reassembly::Limits as ReassemblyLimits;
use crate::analysis::reassembly::ip::OverlapPolicy;
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
    /// Physical input frames. This also bounds persistent capture-scope
    /// metadata: one frame can introduce at most three exact scope identities.
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_flows: usize,
    /// Concurrent IPv4 and IPv6 datagrams retained for fragment reassembly.
    pub max_ip_datagrams: usize,
    /// Physical fragments accepted for any one retained datagram.
    pub max_ip_fragments_per_datagram: usize,
    /// Fragmentable payload bytes accepted for any one datagram.
    pub max_ip_bytes_per_datagram: usize,
    /// Retained IP payload, derived cascade buffers, and conservatively
    /// charged metadata across the run.
    pub max_ip_reassembly_bytes: usize,
    /// Per-datagram terminal outcomes retained for aggregate reporting.
    pub max_ip_outcomes: usize,
    /// Capture-time inactivity after which an incomplete datagram expires.
    pub ip_idle_expiry: Duration,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        let reassembly = ReassemblyLimits::default();
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_flows: DEFAULT_MAX_ANALYSIS_FLOWS,
            max_ip_datagrams: reassembly.max_ip_datagrams,
            max_ip_fragments_per_datagram: reassembly.max_ip_fragments_per_datagram,
            max_ip_bytes_per_datagram: reassembly.max_ip_bytes_per_datagram,
            max_ip_reassembly_bytes: reassembly.max_ip_aggregate_bytes,
            max_ip_outcomes: reassembly.max_ip_retained_outcomes,
            ip_idle_expiry: reassembly.ip_idle_expiry,
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
            ("max_ip_datagrams", self.max_ip_datagrams as u64),
            (
                "max_ip_fragments_per_datagram",
                self.max_ip_fragments_per_datagram as u64,
            ),
            (
                "max_ip_bytes_per_datagram",
                self.max_ip_bytes_per_datagram as u64,
            ),
            (
                "max_ip_reassembly_bytes",
                self.max_ip_reassembly_bytes as u64,
            ),
            ("max_ip_outcomes", self.max_ip_outcomes as u64),
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
        if self.ip_idle_expiry.is_zero() {
            return Err(Error::InvalidLimit {
                field: "ip_idle_expiry",
                value: 0,
                reason: "must be non-zero",
            });
        }
        if Instant::now().checked_add(self.ip_idle_expiry).is_none() {
            return Err(Error::InvalidLimit {
                field: "ip_idle_expiry",
                value: u64::try_from(self.ip_idle_expiry.as_millis()).unwrap_or(u64::MAX),
                reason: "exceeds the platform monotonic-clock range",
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
    /// Deterministic policy applied when IP fragments carry conflicting bytes.
    pub ip_overlap: OverlapPolicy,
    pub limits: Limits,
}
