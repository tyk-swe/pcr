// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Analysis limits and options.

use std::time::{Duration, Instant};

use crate::analysis::pcap::{
    DEFAULT_SIZE_LIMIT, DEFAULT_STREAM_BYTES, DEFAULT_STREAM_FRAMES, Limits as CaptureLimits,
};
use crate::analysis::reassembly::ip::{Limits as IpReassemblyLimits, OverlapPolicy};
use crate::analysis::reassembly::tcp::{
    Limits as TcpReassemblyLimits, MAX_BYTES_PER_FLOW as MAX_TCP_BYTES_PER_FLOW,
};
use crate::filter::Filter;

use crate::analysis::Error;

const DEFAULT_MAX_ANALYSIS_FLOWS: usize = 8_192;

/// Finite resource ceilings for one analysis run.
///
/// Every ceiling either reassembly engine enforces is named here, so a
/// caller can bound the memory a run retains without reaching past this type
/// into the engines. The frame and byte budgets count every frame the
/// capture yields, matched or not, so a display filter can never raise how
/// much input one run reads. The duration budget bounds the run's own
/// processing time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Physical input frames. This also bounds persistent capture-scope
    /// metadata: one frame can introduce at most three exact scope identities.
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    /// Distinct conversations indexed per transport. A TCP conversation
    /// additionally occupies one reassembly flow per direction.
    pub max_flows: usize,
    /// Retained TCP payload bytes in one direction. This is also the
    /// reordering window, so it may not exceed
    /// [`reassembly::tcp::MAX_BYTES_PER_FLOW`](crate::analysis::reassembly::tcp::MAX_BYTES_PER_FLOW).
    pub max_tcp_bytes_per_flow: usize,
    /// Retained TCP payload and conservatively charged metadata across the
    /// run. This is the largest single memory ceiling an analysis run has.
    pub max_tcp_reassembly_bytes: usize,
    /// Pending out-of-order segments retained for any one TCP direction.
    pub max_tcp_segments_per_flow: usize,
    /// Capture-time inactivity after which a TCP flow is evicted.
    pub tcp_idle_expiry: Duration,
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
        let ip = IpReassemblyLimits::default();
        let tcp = TcpReassemblyLimits::default();
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_flows: DEFAULT_MAX_ANALYSIS_FLOWS,
            max_tcp_bytes_per_flow: tcp.max_bytes_per_flow,
            max_tcp_reassembly_bytes: tcp.max_aggregate_bytes,
            max_tcp_segments_per_flow: tcp.max_segments_per_flow,
            tcp_idle_expiry: tcp.idle_expiry,
            max_ip_datagrams: ip.max_datagrams,
            max_ip_fragments_per_datagram: ip.max_fragments_per_datagram,
            max_ip_bytes_per_datagram: ip.max_bytes_per_datagram,
            max_ip_reassembly_bytes: ip.max_aggregate_bytes,
            max_ip_outcomes: ip.max_retained_outcomes,
            ip_idle_expiry: ip.idle_expiry,
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
            ("max_tcp_bytes_per_flow", self.max_tcp_bytes_per_flow as u64),
            (
                "max_tcp_reassembly_bytes",
                self.max_tcp_reassembly_bytes as u64,
            ),
            (
                "max_tcp_segments_per_flow",
                self.max_tcp_segments_per_flow as u64,
            ),
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
        // The per-flow window doubles as the reordering window, so a value
        // reaching the TCP serial half-space makes a retransmission and a
        // wrapped future segment indistinguishable. Refusing it here means a
        // run fails before reading input rather than on its first segment.
        if self.max_tcp_bytes_per_flow > MAX_TCP_BYTES_PER_FLOW {
            return Err(Error::InvalidLimit {
                field: "max_tcp_bytes_per_flow",
                value: self.max_tcp_bytes_per_flow as u64,
                reason: "reaches the TCP serial-number half-space",
            });
        }
        if self.max_duration.is_zero() {
            return Err(Error::InvalidLimit {
                field: "max_duration",
                value: 0,
                reason: "must be non-zero",
            });
        }
        for (field, expiry) in [
            ("tcp_idle_expiry", self.tcp_idle_expiry),
            ("ip_idle_expiry", self.ip_idle_expiry),
        ] {
            if expiry.is_zero() {
                return Err(Error::InvalidLimit {
                    field,
                    value: 0,
                    reason: "must be non-zero",
                });
            }
            if Instant::now().checked_add(expiry).is_none() {
                return Err(Error::InvalidLimit {
                    field,
                    value: u64::try_from(expiry.as_millis()).unwrap_or(u64::MAX),
                    reason: "exceeds the platform monotonic-clock range",
                });
            }
        }
        Ok(())
    }

    /// The aggregate stream bounds the capture reader enforces.
    pub(super) fn capture(&self) -> CaptureLimits {
        CaptureLimits {
            max_frames: self.max_frames,
            max_bytes: self.max_bytes,
        }
    }

    /// The IP reassembler's complete budget set.
    pub(super) fn ip_reassembly(&self) -> IpReassemblyLimits {
        IpReassemblyLimits {
            max_datagrams: self.max_ip_datagrams,
            max_fragments_per_datagram: self.max_ip_fragments_per_datagram,
            max_bytes_per_datagram: self.max_ip_bytes_per_datagram,
            max_aggregate_bytes: self.max_ip_reassembly_bytes,
            max_retained_outcomes: self.max_ip_outcomes,
            idle_expiry: self.ip_idle_expiry,
        }
    }

    /// The TCP reassembler's complete budget set. `max_flows` counts
    /// conversations, which occupy one reassembly flow per direction.
    pub(super) fn tcp_reassembly(&self, directions: usize) -> TcpReassemblyLimits {
        TcpReassemblyLimits {
            max_flows: self.max_flows.saturating_mul(directions),
            max_bytes_per_flow: self.max_tcp_bytes_per_flow,
            max_aggregate_bytes: self.max_tcp_reassembly_bytes,
            max_segments_per_flow: self.max_tcp_segments_per_flow,
            idle_expiry: self.tcp_idle_expiry,
        }
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
