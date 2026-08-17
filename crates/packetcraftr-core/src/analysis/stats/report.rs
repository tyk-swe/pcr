// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public report models for aggregate capture statistics.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Which transport a conversation or port tally belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportKind {
    Tcp,
    Udp,
}

impl TransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One protocol's presence across the matched frames.
///
/// A frame counts once per protocol it contains, however many times the
/// protocol occurs in its stack, and contributes its whole captured length,
/// so a tunnelled frame is visible in full under both its encapsulations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolStat {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

/// One conversation with per-direction tallies.
///
/// Endpoint A is the canonically smaller endpoint, so the same conversation
/// renders identically whichever direction was captured first; `stream` is
/// the index the analysis pipeline assigned, shared with display filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationStat {
    pub transport: TransportKind,
    pub stream: u64,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointStat {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

/// One transport port's tallies, counting source and destination roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortStat {
    pub transport: TransportKind,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

/// One non-empty time bucket of the I/O series.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoBucketStat {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

/// Everything one statistics pass computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
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
}
