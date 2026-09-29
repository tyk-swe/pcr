// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::analysis::{IpReassemblyReport, StreamTransport};

/// Counts each protocol once per matched frame, charging the full captured length.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProtocolStat {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

/// Per-direction conversation tallies; endpoint A sorts before B.
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EndpointStat {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PortStat {
    pub transport: StreamTransport,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct IoBucketStat {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SizeBinStat {
    pub minimum: u32,
    pub maximum: Option<u32>,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub clock: crate::analysis::ClockReport,
    /// Bucket epoch: the first observed matched timestamp, not the minimum.
    pub io_origin: Option<SystemTime>,
    /// Earlier timestamps folded into bucket zero; never silently rebased.
    pub io_underflow_frames: u64,
    pub interval: Duration,
    pub frames: u64,
    pub bytes: u64,
    pub first_timestamp: Option<SystemTime>,
    pub last_timestamp: Option<SystemTime>,
    /// Sorted by frame count descending, then name, for stable reports.
    pub protocols: Vec<ProtocolStat>,
    pub conversations: Vec<ConversationStat>,
    pub endpoints: Vec<EndpointStat>,
    pub ports: Vec<PortStat>,
    pub io: Vec<IoBucketStat>,
    /// Capture-global fragment accounting, independent of the display filter.
    pub ip_reassembly: IpReassemblyReport,
    pub interfaces: Vec<crate::capture_file::Interface>,
    pub sizes: Vec<SizeBinStat>,
    pub tcp_timing: Vec<super::TcpTimingStat>,
}

impl Report {
    pub fn duration(&self) -> Option<Duration> {
        let (first, last) = self.first_timestamp.zip(self.last_timestamp)?;
        Some(last.duration_since(first).unwrap_or(Duration::ZERO))
    }

    pub fn average_packet_size(&self) -> Option<f64> {
        (self.frames > 0).then(|| self.bytes as f64 / self.frames as f64)
    }

    pub fn packet_rate(&self) -> Option<f64> {
        self.rate(self.frames)
    }

    pub fn byte_rate(&self) -> Option<f64> {
        self.rate(self.bytes)
    }

    fn rate(&self, count: u64) -> Option<f64> {
        let seconds = self.duration()?.as_secs_f64();
        (seconds > 0.0).then(|| count as f64 / seconds)
    }
}
