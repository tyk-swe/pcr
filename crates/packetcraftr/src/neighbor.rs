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
pub use model::Resolution;
pub(crate) use model::{MAX_VLAN_TAGS, Request};
pub(crate) use options::Bounds;
pub use options::Options;
pub(crate) use resolver::{Active, State};
pub(crate) use wire::build_request_frame as request_frame;

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

/// The extra transmissions and wire bytes one stage reserves for `packets`
/// probes at `attempts` neighbor requests each on a link-layer route. An
/// unanswered resolution is not remembered, so every probe may ask again.
/// Returns `(0, 0)` for a layer-3 route or a multicast or broadcast address,
/// whose link address is deterministic, and `None` on overflow. `address` is
/// `None` when the family is unknown before resolution, which charges the
/// larger solicitation.
pub(crate) fn charge(
    link_mode: packetcraftr_netio::link::Mode,
    address: Option<std::net::IpAddr>,
    packets: u64,
    attempts: u64,
) -> Option<(u64, u64)> {
    if link_mode == packetcraftr_netio::link::Mode::Layer3 {
        return Some((0, 0));
    }
    let request_bytes = match address {
        Some(address) if !needs_resolution(address) => return Some((0, 0)),
        Some(address) => request_wire_bytes(address),
        None => IPV6_REQUEST_BYTES,
    };
    let requests = packets.checked_mul(attempts)?;
    Some((requests, requests.checked_mul(request_bytes)?))
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_netio::link::Mode;

    #[test]
    fn link_layer_unicast_charges_one_request_per_packet() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let (packets, bytes) = super::charge(Mode::Layer2, Some(address), 3, 2).unwrap();
        assert_eq!(packets, 6);
        assert_eq!(bytes, 6 * super::IPV4_REQUEST_BYTES);
    }

    #[test]
    fn multicast_and_layer3_charge_nothing() {
        let multicast = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            super::charge(Mode::Layer2, Some(multicast), 3, 2),
            Some((0, 0))
        );
        let unicast = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            super::charge(Mode::Layer3, Some(unicast), 3, 2),
            Some((0, 0))
        );
    }

    #[test]
    fn unknown_family_charges_the_larger_solicitation() {
        let (_, bytes) = super::charge(Mode::Layer2, None, 1, 1).unwrap();
        assert_eq!(bytes, super::IPV6_REQUEST_BYTES);
    }
}
