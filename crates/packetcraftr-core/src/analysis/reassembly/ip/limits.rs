// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite resource and expiry bounds for IP fragment reassembly.

use std::time::Duration;

const DEFAULT_MAX_DATAGRAMS: usize = 8_192;
const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 256;
const DEFAULT_MAX_BYTES_PER_DATAGRAM: usize = 65_535;
const DEFAULT_MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_RETAINED_OUTCOMES: usize = 8_192;
const DEFAULT_IDLE_EXPIRY: Duration = Duration::from_secs(30);

/// Every ceiling the IP reassembler enforces.
///
/// The engine reads no budget outside this struct, so a caller that fills
/// every field has named every bound on the memory one reassembly run
/// retains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently retained IPv4 and IPv6 datagrams.
    pub max_datagrams: usize,
    /// Maximum physical fragments admitted to one retained datagram.
    pub max_fragments_per_datagram: usize,
    /// Maximum fragmentable payload extent retained for one datagram.
    pub max_bytes_per_datagram: usize,
    /// Maximum retained payload, reconstruction bytes, and conservatively
    /// charged metadata across all datagrams.
    pub max_aggregate_bytes: usize,
    /// Maximum per-datagram outcomes one expiry sweep may name.
    pub max_retained_outcomes: usize,
    /// Capture-time inactivity after which an incomplete datagram expires.
    pub idle_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_datagrams: DEFAULT_MAX_DATAGRAMS,
            max_fragments_per_datagram: DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            max_bytes_per_datagram: DEFAULT_MAX_BYTES_PER_DATAGRAM,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_retained_outcomes: DEFAULT_MAX_RETAINED_OUTCOMES,
            idle_expiry: DEFAULT_IDLE_EXPIRY,
        }
    }
}
