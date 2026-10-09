// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Independently authored discovery addresses and injected route topology.

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::LinkType;
use packetcraftr_netio::interface::Id;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::route::{Decision, Provider, Scope, SelectionReason};
use std::convert::Infallible;
use std::net::IpAddr;

pub(crate) fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../docs/scanner-corpus.v1.json")).unwrap()
}

pub(crate) fn family_addresses(v4: bool) -> [IpAddr; 3] {
    let corpus = corpus();
    let addresses = &corpus["fixture_addresses"][if v4 { "ipv4" } else { "ipv6" }];
    ["source", "destination", "router"].map(|key| addresses[key].as_str().unwrap().parse().unwrap())
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Routes {
    pub(crate) routed: bool,
    pub(crate) layer2: bool,
}

impl Provider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<Decision, Infallible> {
        Ok(Decision {
            interface: Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: self.layer2.then_some(super::INTERFACE_MAC),
            selected_source: Some(family_addresses(destination.is_ipv4())[0]),
            preferred_source: None,
            next_hop: self
                .routed
                .then_some(family_addresses(destination.is_ipv4())[2]),
            selection_reason: if self.routed {
                SelectionReason::Gateway
            } else {
                SelectionReason::OnLink
            },
            destination_scope: if self.routed {
                Scope::Global
            } else {
                Scope::Link
            },
            mtu: 1500,
            capability: if self.layer2 {
                Capability::Layer2AndLayer3
            } else {
                Capability::Layer3
            },
            link_type: if self.layer2 {
                LinkType::ETHERNET
            } else {
                LinkType::RAW
            },
        })
    }
}
