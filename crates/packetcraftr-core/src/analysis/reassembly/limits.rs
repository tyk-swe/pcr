// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

const DEFAULT_MAX_REASSEMBLY_FLOWS: usize = 8_192;
const DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW: usize = 4_096;
const DEFAULT_MAX_IP_DATAGRAMS: usize = 8_192;
const DEFAULT_MAX_IP_FRAGMENTS_PER_DATAGRAM: usize = 256;
const DEFAULT_MAX_IP_BYTES_PER_DATAGRAM: usize = 65_535;
const DEFAULT_MAX_IP_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_IP_RETAINED_OUTCOMES: usize = 8_192;

/// Separate resource and expiry bounds for TCP and IP reassembly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently retained TCP directions.
    pub max_flows: usize,
    /// Maximum retained TCP bytes in one direction.
    pub max_bytes_per_flow: usize,
    /// Maximum retained TCP payload and conservatively charged metadata.
    pub max_aggregate_bytes: usize,
    pub max_tcp_segments_per_flow: usize,
    pub tcp_idle_expiry: Duration,
    /// Maximum concurrently retained IPv4 and IPv6 datagrams.
    pub max_ip_datagrams: usize,
    /// Maximum physical fragments admitted to one retained IP datagram.
    pub max_ip_fragments_per_datagram: usize,
    /// Maximum fragmentable payload extent retained for one IP datagram.
    pub max_ip_bytes_per_datagram: usize,
    /// Maximum retained IP payload, reconstruction bytes, and conservatively
    /// charged metadata across all datagrams.
    pub max_ip_aggregate_bytes: usize,
    /// Maximum per-datagram IP outcomes an aggregate consumer may retain.
    pub max_ip_retained_outcomes: usize,
    pub ip_idle_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_REASSEMBLY_FLOWS,
            max_bytes_per_flow: DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW,
            max_aggregate_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
            max_tcp_segments_per_flow: DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW,
            tcp_idle_expiry: Duration::from_secs(120),
            max_ip_datagrams: DEFAULT_MAX_IP_DATAGRAMS,
            max_ip_fragments_per_datagram: DEFAULT_MAX_IP_FRAGMENTS_PER_DATAGRAM,
            max_ip_bytes_per_datagram: DEFAULT_MAX_IP_BYTES_PER_DATAGRAM,
            max_ip_aggregate_bytes: DEFAULT_MAX_IP_AGGREGATE_BYTES,
            max_ip_retained_outcomes: DEFAULT_MAX_IP_RETAINED_OUTCOMES,
            ip_idle_expiry: Duration::from_secs(30),
        }
    }
}
