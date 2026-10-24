// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

mod cache;
mod error;
mod evidence;
mod model;
mod options;
mod resolver;
mod wire;

pub use error::{Error, FailureEvidence};
pub use model::{MAX_VLAN_TAGS, Request, Resolution};
pub use options::Options;
pub(crate) use resolver::{Resolver, State, request_frame};

// Allowance for one ARP request or NDP neighbor solicitation: Ethernet
// padding for ARP, a source link-address option for NDP, and the largest
// VLAN tag stack a route may add to either.
const VLAN_STACK_BYTES: u64 = 4 * MAX_VLAN_TAGS as u64;
pub(crate) const IPV4_REQUEST_BYTES: u64 = 60 + VLAN_STACK_BYTES;
pub(crate) const IPV6_REQUEST_BYTES: u64 = 14 + 40 + 32 + VLAN_STACK_BYTES;

/// Whether `address` requires link-layer neighbor resolution rather than a
/// deterministic multicast or broadcast mapping.
pub(crate) fn needs_resolution(address: std::net::IpAddr) -> bool {
    !address.is_multicast() && address != std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

/// Worst-case wire byte allowance for one ARP request or NDP solicitation for `address`.
pub(crate) const fn request_wire_bytes(address: std::net::IpAddr) -> u64 {
    if address.is_ipv4() {
        IPV4_REQUEST_BYTES
    } else {
        IPV6_REQUEST_BYTES
    }
}

/// Exchange statistics for a neighbor resolution that sent `attempts` copies of
/// a `frame_bytes`-byte request frame.
pub(crate) fn stats(
    attempts: u32,
    frame_bytes: usize,
    elapsed: std::time::Duration,
    capture: packetcraftr_netio::capture::Stats,
) -> crate::Stats {
    let attempts = u64::from(attempts);
    crate::Stats {
        packets_attempted: attempts,
        packets_completed: attempts,
        bytes: attempts.saturating_mul(frame_bytes as u64),
        elapsed,
        capture,
    }
}
