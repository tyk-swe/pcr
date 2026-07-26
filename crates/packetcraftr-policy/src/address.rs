// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Address-scope classification used by destination policy.

use std::net::IpAddr;

pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_multicast()
                || !(address.is_private()
                    || address.is_loopback()
                    || address.is_link_local()
                    || address.is_unspecified()
                    || address.is_documentation())
        }
        IpAddr::V6(address) => {
            address.is_multicast()
                || !(address.is_loopback()
                    || address.is_unspecified()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
                    || is_ipv6_documentation(address))
        }
    }
}

fn is_ipv6_documentation(address: std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}
