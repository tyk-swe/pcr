// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;
use std::net::IpAddr;

/// PTR name: reversed IPv4 octets under `in-addr.arpa`, or all 32 IPv6 nibbles
/// reversed under `ip6.arpa`.
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::reverse_name;

    #[test]
    fn ipv4_addresses_reverse_octets_under_in_addr_arpa() {
        assert_eq!(
            reverse_name(Ipv4Addr::new(192, 0, 2, 1).into()),
            "1.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name(Ipv4Addr::LOCALHOST.into()),
            "1.0.0.127.in-addr.arpa"
        );
    }

    #[test]
    fn ipv6_addresses_reverse_all_thirty_two_nibbles_under_ip6_arpa() {
        // 2001:db8::1 expands to 32 nibbles; leading zero groups are present.
        assert_eq!(
            reverse_name(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            reverse_name(Ipv6Addr::LOCALHOST.into()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn derived_names_are_valid_dns_questions() {
        for address in [
            "192.0.2.1".parse().unwrap(),
            "2001:db8::ff00:42".parse().unwrap(),
        ] {
            let name = reverse_name(address);
            assert!(name.len() <= 253);
            crate::dns::canonical_query_name(&name).expect("derived name is a valid DNS name");
        }
    }
}
