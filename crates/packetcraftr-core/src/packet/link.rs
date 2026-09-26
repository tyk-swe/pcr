// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing and VLAN tags shared by packet inspection, routing,
//! and neighbor discovery.

use std::fmt;
use std::net::IpAddr;

/// A 48-bit IEEE 802 MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The Ethernet group address an IP multicast destination maps to
    /// (RFC 1112 section 6.4 for IPv4, RFC 2464 section 7 for IPv6), or
    /// `None` when `destination` is not multicast.
    pub fn for_ip_multicast(destination: IpAddr) -> Option<Self> {
        match destination {
            IpAddr::V4(address) if address.is_multicast() => {
                let [_, b, c, d] = address.octets();
                Some(Self([0x01, 0x00, 0x5e, b & 0x7f, c, d]))
            }
            IpAddr::V6(address) if address.is_multicast() => {
                let [.., a, b, c, d] = address.octets();
                Some(Self([0x33, 0x33, a, b, c, d]))
            }
            _ => None,
        }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

impl VlanKind {
    /// The EtherType that announces a tag of this kind.
    pub const fn ether_type(self) -> u16 {
        match self {
            Self::Ieee8021Q => 0x8100,
            Self::Ieee8021Ad => 0x88a8,
        }
    }

    /// The tag kind an EtherType announces, or `None` when it announces no
    /// VLAN tag.
    pub const fn from_ether_type(ether_type: u16) -> Option<Self> {
        match ether_type {
            0x8100 => Some(Self::Ieee8021Q),
            0x88a8 => Some(Self::Ieee8021Ad),
            _ => None,
        }
    }
}

/// One fixed-width VLAN tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl VlanTag {
    /// Splits a wire Tag Control Information word into priority (PCP), drop
    /// eligibility (DEI), and VLAN ID.
    pub const fn from_tci(kind: VlanKind, tci: u16) -> Self {
        Self {
            kind,
            priority: (tci >> 13) as u8,
            drop_eligible: tci & 0x1000 != 0,
            vlan_id: tci & 0x0fff,
        }
    }

    /// The wire Tag Control Information word. Out-of-range priority and VLAN
    /// ID bits are masked, so check them before encoding untrusted values.
    pub const fn tci(self) -> u16 {
        ((self.priority as u16 & 7) << 13)
            | if self.drop_eligible { 1 << 12 } else { 0 }
            | (self.vlan_id & 0x0fff)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn ip_multicast_groups_map_to_their_ethernet_group_addresses() {
        assert_eq!(
            MacAddress::for_ip_multicast(IpAddr::V4(Ipv4Addr::new(239, 255, 1, 2))),
            Some(MacAddress([0x01, 0x00, 0x5e, 0x7f, 1, 2])),
            "only the low 23 IPv4 group bits are mapped"
        );
        assert_eq!(
            MacAddress::for_ip_multicast(IpAddr::V6(
                "ff02::1:ff00:abcd".parse::<Ipv6Addr>().expect("group")
            )),
            Some(MacAddress([0x33, 0x33, 0xff, 0x00, 0xab, 0xcd]))
        );
        for unicast in [
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert_eq!(MacAddress::for_ip_multicast(unicast), None);
        }
    }
}
