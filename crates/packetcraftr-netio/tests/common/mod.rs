// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Every integration test binary compiles this module separately and uses
// only the fixtures it needs.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::{
    interface::Id as InterfaceId,
    link::Capability,
    route::{Decision, Scope, SelectionReason},
};

pub(crate) fn interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 4,
    }
}

/// A gateway route out of `fixture0` on a private network.
pub(crate) fn decision(capability: Capability) -> Decision {
    Decision {
        interface: interface(),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        preferred_source: None,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability,
        link_type: LinkType::ETHERNET,
    }
}

/// The destination `decision` was looked up for.
pub(crate) fn lookup_destination() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
}
