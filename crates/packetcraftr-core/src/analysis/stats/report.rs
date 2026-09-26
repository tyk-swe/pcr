// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::analysis::{IpReassemblyReport, StreamTransport};

/// Counts each protocol once per matched frame and charges the full captured
/// length, including for each encapsulation in a tunnel.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProtocolStat {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

/// Per-direction conversation tallies. Endpoint A sorts before B; `stream` is
/// the pipeline-assigned index shared with display filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationStat {
    pub transport: StreamTransport,
    pub stream: u64,
    pub scope: crate::analysis::scope::Definition,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub frames_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub frames_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub first_timestamp: SystemTime,
    pub last_timestamp: SystemTime,
}

impl ConversationStat {
    pub fn duration(&self) -> Duration {
        self.last_timestamp
            .duration_since(self.first_timestamp)
            .unwrap_or(Duration::ZERO)
    }
}

/// One IP endpoint's transmit and receive tallies.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EndpointStat {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

/// One transport port's tallies, counting source and destination roles.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PortStat {
    pub transport: StreamTransport,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

/// One non-empty time bucket of the I/O series.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct IoBucketStat {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub clock: crate::analysis::ClockReport,
    /// Stable bucket epoch (first observed matched timestamp), independently
    /// of `first_timestamp`, which is the minimum matched timestamp.
    pub io_origin: Option<SystemTime>,
    /// Earlier timestamps folded into bucket zero; never silently rebased.
    pub io_underflow_frames: u64,
    /// I/O bucket width the series was computed with.
    pub interval: Duration,
    /// Matched frames and their captured bytes.
    pub frames: u64,
    pub bytes: u64,
    pub first_timestamp: Option<SystemTime>,
    pub last_timestamp: Option<SystemTime>,
    /// Sorted by frame count descending, then name, for stable reports.
    pub protocols: Vec<ProtocolStat>,
    /// Sorted by transport, then assigned conversation index.
    pub conversations: Vec<ConversationStat>,
    /// Sorted by address.
    pub endpoints: Vec<EndpointStat>,
    /// Sorted by transport, then port.
    pub ports: Vec<PortStat>,
    /// Non-empty buckets in time order, offset from the first matched frame.
    pub io: Vec<IoBucketStat>,
    /// Capture-global fragment accounting, intentionally independent of the
    /// downstream display filter because every physical fragment must update
    /// reassembly state. This never contributes synthesized frames or derived
    /// bytes to [`Self::frames`] or [`Self::bytes`].
    pub ip_reassembly: IpReassemblyReport,
    /// Interface descriptions the capture source declared, in the global
    /// interface-ID order frames reference. Classic PCAP always contributes
    /// exactly one entry; a PCAPNG source with no interface descriptions
    /// yields an empty list rather than invented values.
    pub interfaces: Vec<crate::capture_file::Interface>,
}

impl Report {
    /// Span between the earliest and latest matched timestamps, regardless of
    /// arrival order. `None` if no frame matched; matched frames always have
    /// timestamps.
    pub fn duration(&self) -> Option<Duration> {
        let (first, last) = self.first_timestamp.zip(self.last_timestamp)?;
        Some(last.duration_since(first).unwrap_or(Duration::ZERO))
    }

    /// Mean captured length over matched frames, in bytes.
    ///
    /// `None` for an empty match set; the value is otherwise `bytes /
    /// frames` computed in floating point, so sub-byte means are not
    /// truncated.
    pub fn average_packet_size(&self) -> Option<f64> {
        (self.frames > 0).then(|| self.bytes as f64 / self.frames as f64)
    }

    /// Matched frames per second over [`Self::duration`].
    ///
    /// `None` when no duration is available or it is zero — a single
    /// instant cannot define a rate, and dividing by it would produce an
    /// infinite or NaN result rather than a statistic.
    pub fn packet_rate(&self) -> Option<f64> {
        self.rate(self.frames)
    }

    /// Matched captured bytes per second over [`Self::duration`], under the
    /// same availability rules as [`Self::packet_rate`].
    pub fn byte_rate(&self) -> Option<f64> {
        self.rate(self.bytes)
    }

    /// `count` spread over [`Self::duration`], under the availability rules
    /// [`Self::packet_rate`] documents.
    fn rate(&self, count: u64) -> Option<f64> {
        let seconds = self.duration()?.as_secs_f64();
        (seconds > 0.0).then(|| count as f64 / seconds)
    }
}
