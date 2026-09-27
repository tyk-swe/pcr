// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::interface::Id as InterfaceId;
use crate::link::Capability;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    Local,
    OnLink,
    Broadcast,
    Gateway,
    InterfaceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub interface: InterfaceId,
    pub source_mac: Option<MacAddress>,
    pub selected_source: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: SelectionReason,
    pub destination_scope: Scope,
    pub mtu: u32,
    pub capability: Capability,
    pub link_type: LinkType,
}
