// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

const DEFAULT_MAX_REASSEMBLY_FLOWS: usize = 8_192;
const DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW: usize = 1024 * 1024;
const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW: usize = 4_096;

/// Resource and expiry bounds for TCP reassembly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_flows: usize,
    pub max_bytes_per_flow: usize,
    pub max_aggregate_bytes: usize,
    pub max_tcp_segments_per_flow: usize,
    pub tcp_idle_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_REASSEMBLY_FLOWS,
            max_bytes_per_flow: DEFAULT_MAX_REASSEMBLY_BYTES_PER_FLOW,
            max_aggregate_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
            max_tcp_segments_per_flow: DEFAULT_MAX_TCP_SEGMENTS_PER_FLOW,
            tcp_idle_expiry: Duration::from_secs(120),
        }
    }
}
