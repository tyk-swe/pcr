// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::frame::{Frame, LinkType};

use crate::{
    capture::Statistics,
    interface::Id,
    link::{MacAddress, VlanTag},
};

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
