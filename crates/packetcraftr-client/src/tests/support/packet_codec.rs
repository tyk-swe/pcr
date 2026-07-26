// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::*;
pub(crate) fn route(mode: LinkCapability) -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        },
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        next_hop: None,
        selection_reason: RouteSelectionReason::OnLink,
        destination_scope: DestinationScope::Private,
        mtu: 1500,
        capability: mode,
        link_type: LinkType::IPV4,
    }
}

pub(crate) fn packet(source: Ipv4Addr, destination: Ipv4Addr, sport: u16, dport: u16) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: sport,
            destination_port: dport,
            ..Udp::default()
        });
    packet
}

pub(crate) fn prepared_exchange_packet(
    built: BuiltPacket,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> PreparedExchangePacket {
    PreparedExchangePacket {
        built,
        route: MaterializedRoute {
            plan: PlannedRoute {
                route: route(LinkCapability::Layer3),
                mode: LinkMode::Layer3,
                lookup_destination: Some(IpAddr::V4(destination)),
                final_destination: Some(IpAddr::V4(destination)),
                visited_destinations: vec![IpAddr::V4(destination)],
                packet_source: Some(IpAddr::V4(source)),
                neighbor_source: Some(IpAddr::V4(source)),
                neighbor_target: Some(IpAddr::V4(destination)),
                destination_mac: None,
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        },
    }
}

pub(crate) fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
    let base = || {
        packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        )
    };

    let mut ethernet = base();
    ethernet.insert(0, Ethernet::default()).unwrap();

    let mut customer_vlan_root = base();
    customer_vlan_root.insert(0, Vlan::default()).unwrap();

    let mut service_vlan_root = base();
    service_vlan_root.insert(0, Vlan8021ad::default()).unwrap();

    let mut ethernet_stacked = base();
    ethernet_stacked
        .insert(
            0,
            Vlan {
                vlan_id: 200,
                ..Vlan::default()
            },
        )
        .unwrap();
    ethernet_stacked
        .insert(
            0,
            Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            },
        )
        .unwrap();
    ethernet_stacked.insert(0, Ethernet::default()).unwrap();

    let mut vlan_rooted_stacked = base();
    vlan_rooted_stacked
        .insert(
            0,
            Vlan {
                vlan_id: 200,
                ..Vlan::default()
            },
        )
        .unwrap();
    vlan_rooted_stacked
        .insert(
            0,
            Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            },
        )
        .unwrap();

    vec![
        ("ethernet", ethernet),
        ("vlan", customer_vlan_root),
        ("vlan8021ad", service_vlan_root),
        ("ethernet-stacked-vlan", ethernet_stacked),
        ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
    ]
}

pub(crate) fn exchange_with_capture_statistics(
    statistics: CaptureStatistics,
    overflow_policy: CaptureOverflowPolicy,
) -> Result<ExchangeResult, ClientError> {
    let io = ScriptedExchangeIo {
        events: Arc::new(Mutex::new(Vec::new())),
        response: Arc::new(Mutex::new(None)),
        deliver_before_send: false,
        limits: Arc::new(Mutex::new(Vec::new())),
        capture_statistics: statistics,
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    client.exchange(
        &PacketTemplate::new(packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        )),
        ExchangeOptions {
            send: SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
            capture_overflow_policy: overflow_policy,
            ..ExchangeOptions::default()
        },
    )
}
