// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::frame::{Frame, LinkType};

use crate::{capture::Statistics, interface::Id, link::MacAddress};

/// Maximum explicit VLAN headers copied into a neighbor-discovery request.
pub(crate) const MAX_VLAN_TAGS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}

/// One fixed-width tag copied from a packet's explicit VLAN stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

/// Interface-owned context for one active ARP/NDP lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub interface: Id,
    pub interface_source: IpAddr,
    pub interface_mac: MacAddress,
    pub target: IpAddr,
    pub vlan_tags: Vec<VlanTag>,
    pub mtu: u32,
    pub link_type: LinkType,
}

/// Bounded evidence returned by an active resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub mac_address: MacAddress,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<Frame>,
    pub evidence_truncated: bool,
    pub capture_statistics: Statistics,
}
