// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing and VLAN tags shared by packet inspection, routing,
//! and neighbor discovery.

use std::fmt;

/// A 48-bit IEEE 802 MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

/// The tagging standard of one VLAN header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}

/// One fixed-width VLAN tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}
