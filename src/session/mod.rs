// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded flow, fragment, and TCP stream session stages.

pub mod fragment;
pub mod tcp;

use std::time::Duration;

const DEFAULT_MAX_REASSEMBLY_FLOWS: usize = 8_192;
const DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 256;
const DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW: usize = 4_096;

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

/// Backward-compatible name for [`ReassemblyLimits`].
pub use ReassemblyLimits as Limits;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn preferred_public_reassembly_names_are_usable() {
        let limits = super::ReassemblyLimits::default();
        let reassembler =
            super::fragment::Reassembler::new(limits, super::fragment::OverlapPolicy::default());
        assert_eq!(reassembler.flow_count(), 0);

        let key = super::fragment::DatagramKey {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::LOCALHOST),
            identification: 1,
            next_header: 17,
        };
        let legacy_key: super::fragment::Key = key.clone();
        assert_eq!(legacy_key, key);
    }
}
