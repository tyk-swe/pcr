// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::Error;
use crate::field::parse_mac;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The Ethernet broadcast address, `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The Ethernet group address an IP multicast destination maps to
    /// (RFC 1112 section 6.4 for IPv4, RFC 2464 section 7 for IPv6).
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

impl FromStr for MacAddress {
    type Err = Error;

    /// Accepts six two-digit hexadecimal bytes joined by one repeated `:` or `-`, in upper- or
    /// lower-case digits; [`fmt::Display`] writes lower-case with `:`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_mac(text).map(Self).ok_or(Error::InvalidMacAddress)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

impl VlanKind {
    pub const fn ether_type(self) -> u16 {
        match self {
            Self::Ieee8021Q => 0x8100,
            Self::Ieee8021Ad => 0x88a8,
        }
    }

    pub const fn from_ether_type(ether_type: u16) -> Option<Self> {
        match ether_type {
            0x8100 => Some(Self::Ieee8021Q),
            0x88a8 => Some(Self::Ieee8021Ad),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl VlanTag {
    pub const fn from_tci(kind: VlanKind, tci: u16) -> Self {
        Self {
            kind,
            priority: (tci >> 13) as u8,
            drop_eligible: tci & 0x1000 != 0,
            vlan_id: tci & 0x0fff,
        }
    }

    /// Out-of-range priority and VLAN ID bits are masked, so check them before encoding untrusted values.
    pub const fn tci(self) -> u16 {
        ((self.priority as u16 & 7) << 13)
            | if self.drop_eligible { 1 << 12 } else { 0 }
            | (self.vlan_id & 0x0fff)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn malformed_mac_addresses_are_refused() {
        for text in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:01:02",
            "02:00:00:00:00:01:",
            "02:00-00:00:00:01",
            "02-00:00-00:00-01",
            "0200.0000.0001",
            "020000000001",
            "2:0:0:0:0:1",
            "002:00:00:00:00:01",
            "02:00:00:00:00:0g",
            "+2:00:00:00:00:01",
            "02:00:00:00:00:-1",
            " 02:00:00:00:00:01",
        ] {
            assert_eq!(
                text.parse::<MacAddress>(),
                Err(Error::InvalidMacAddress),
                "{text:?}"
            );
        }
    }
}
