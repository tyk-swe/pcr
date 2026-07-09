// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded flow, fragment, and TCP stream session stages.

mod fragment;
mod tcp;

use std::time::Duration;

pub use fragment::{
    Fragment, FragmentError, FragmentKey, FragmentOverlapPolicy, FragmentReassembler,
    FragmentReassemblyEvent, ReassembledDatagram,
};
pub use tcp::{TcpFlowKey, TcpReassembler, TcpReassemblyError, TcpReassemblyEvent, TcpSegment};

pub const DEFAULT_MAX_REASSEMBLY_FLOWS: usize = 8_192;
pub const DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW: usize = 1024 * 1024;
pub const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 256;
pub const DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    pub max_flows: usize,
    pub max_bytes_per_flow: usize,
    pub max_aggregate_bytes: usize,
    pub max_fragments_per_datagram: usize,
    pub max_tcp_segments_per_flow: usize,
    pub fragment_expiry: Duration,
    pub tcp_idle_expiry: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_REASSEMBLY_FLOWS,
            max_bytes_per_flow: DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW,
            max_aggregate_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
            max_fragments_per_datagram: DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            max_tcp_segments_per_flow: DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW,
            fragment_expiry: Duration::from_secs(30),
            tcp_idle_expiry: Duration::from_secs(120),
        }
    }
}
