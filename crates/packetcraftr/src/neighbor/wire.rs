// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP and NDP discovery frames, built from core layers and read through the
//! dissector. No Ethernet, ARP, or NDP bytes are written or parsed by hand.

use packetcraftr_core::packet::MacAddress;

mod reply;
mod request;
#[cfg(test)]
mod tests;

pub(super) use reply::match_neighbor_response;
pub(super) use request::build_request_frame;

/// Whether `address` names one interface: not the zero, broadcast, or a
/// group address.
pub(super) fn is_unicast_mac(address: MacAddress) -> bool {
    address.0 != [0; 6] && address.0 != [0xff; 6] && address.0[0] & 1 == 0
}
