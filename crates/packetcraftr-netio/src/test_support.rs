// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr_core::frame::LinkType;

use crate::interface::{self, Id};
use crate::link::Capability;

pub(crate) fn interface_id(name: &str, index: u32) -> Id {
    Id {
        name: name.to_owned(),
        index,
    }
}

pub(crate) fn interface_info(name: &str, index: u32) -> interface::Info {
    interface::Info {
        id: interface_id(name, index),
        description: None,
        mac_address: None,
        addresses: Vec::new(),
        flags: interface::Flags::default(),
        mtu: Some(1_500),
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

pub(crate) fn assigned(address: IpAddr, prefix_length: u8) -> interface::Address {
    interface::Address {
        address,
        prefix_length,
    }
}

pub(crate) fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[cfg(native_layer2)]
pub(crate) fn capture_metadata(name: &str, index: u32) -> crate::capture::Metadata {
    crate::capture::Metadata {
        interface: interface_id(name, index),
        link_type: LinkType::ETHERNET,
        snap_length: 64,
        native: Default::default(),
    }
}
