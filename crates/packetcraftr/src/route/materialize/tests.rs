// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::interface;
use packetcraftr_netio::link::{Capability, Mode};
use packetcraftr_netio::route::{Decision, Scope, SelectionReason};

fn plan() -> Plan {
    Plan {
        decision: Decision {
            interface: interface::Id {
                index: 1,
                name: "test0".into(),
            },
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_source: Some("192.0.2.1".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 1500,
            capability: Capability::Layer2,
            link_type: LinkType::ETHERNET,
        },
        mode: Mode::Layer2,
        lookup_destination: Some("192.0.2.2".parse().unwrap()),
        final_destination: Some("192.0.2.2".parse().unwrap()),
        visited_destinations: Vec::new(),
        packet_source: Some("192.0.2.1".parse().unwrap()),
        neighbor_source: Some("192.0.2.1".parse().unwrap()),
        neighbor_target: Some("192.0.2.2".parse().unwrap()),
        destination_mac: Some(MacAddress([2, 0, 0, 0, 0, 2])),
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    }
}

#[test]
fn neighbor_stats_report_the_resolutions_request_bytes() {
    let resolution = NeighborResolution {
        mac_address: MacAddress([2, 0, 0, 0, 0, 2]),
        attempts: 3,
        request_bytes: 60,
        cache_hit: false,
        captured: Vec::new(),
        evidence_truncated: false,
        capture_statistics: Default::default(),
    };
    let materialized = Materialized {
        plan: plan(),
        neighbor_resolution: Some(resolution),
    };
    let stats = materialized.neighbor_stats().unwrap();
    assert_eq!(stats.packets_attempted, 3);
    assert_eq!(stats.bytes, 180);
}

#[test]
fn neighbor_stats_are_empty_without_a_resolution() {
    let materialized = Materialized {
        plan: plan(),
        neighbor_resolution: None,
    };
    let stats = materialized.neighbor_stats().unwrap();
    assert_eq!(stats.packets_attempted, 0);
    assert_eq!(stats.bytes, 0);
}
