// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;
use std::net::IpAddr;

/// PTR name: reversed IPv4 octets under `in-addr.arpa` or IPv6 nibbles under `ip6.arpa`.
pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(address) => {
            let mut name = String::with_capacity(32 * 2 + "ip6.arpa".len());
            for byte in address.octets().iter().rev() {
                for nibble in [byte & 0x0f, byte >> 4] {
                    let _ = write!(name, "{nibble:x}.");
                }
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}
