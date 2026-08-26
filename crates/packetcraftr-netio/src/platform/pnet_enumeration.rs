// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Legacy Unix interface-enumeration adapter used by the default feature.

#![forbid(unsafe_code)]

use crate::{
    interface::{self, Id as InterfaceId},
    link::{Capability, MacAddress},
};
use packetcraftr_core::frame::LinkType;

pub(super) fn interfaces() -> Vec<interface::Info> {
    pnet_datalink::interfaces()
        .into_iter()
        .map(|interface| {
            let flags = interface::Flags {
                up: interface.is_up(),
                broadcast: interface.is_broadcast(),
                loopback: interface.is_loopback(),
                point_to_point: interface.is_point_to_point(),
                multicast: interface.is_multicast(),
            };
            let mac_address = interface.mac.map(|address| MacAddress(address.octets()));
            let loopback = interface.is_loopback();
            let ethernet = !loopback && mac_address.is_some();
            let addresses = interface
                .ips
                .into_iter()
                .map(|network| interface::Address {
                    address: network.ip(),
                    prefix_length: network.prefix(),
                })
                .collect();
            interface::Info {
                id: InterfaceId {
                    name: interface.name,
                    index: interface.index,
                },
                description: (!interface.description.is_empty()).then_some(interface.description),
                mac_address,
                addresses,
                flags,
                mtu: None,
                capability: if ethernet {
                    Capability::Layer2AndLayer3
                } else {
                    Capability::Layer3
                },
                link_type: if ethernet {
                    LinkType::ETHERNET
                } else {
                    LinkType::RAW
                },
            }
        })
        .collect()
}
