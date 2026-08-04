// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Bytes, CaptureStatistics, Ethernet, FixedRoute, Frame, InterfaceId, InterfaceOnlyRoute, IpAddr,
    Ipv4, Ipv4Addr, LinkMode, LinkType, MacAddress, Mutex, NeighborError, NeighborRequest,
    NeighborResolution, NeighborVlanKind, NeighborVlanTag, NeverResolve, Ordering, Packet,
    PlanError, PlanOptions, Raw, RecordingResolver, RouteDecision, RoutePlanner, Vlan, Vlan8021ad,
    WireValue, route,
};

#[test]
fn on_link_and_gateway_neighbor_targets_are_family_independent() {
    let cases = [
        (
            "IPv4 on-link",
            "192.0.2.10".parse().unwrap(),
            "192.0.2.20".parse().unwrap(),
            None,
        ),
        (
            "IPv4 gateway",
            "192.0.2.10".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            Some("192.0.2.1".parse().unwrap()),
        ),
        (
            "IPv6 on-link",
            "2001:db8::10".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
            None,
        ),
        (
            "IPv6 gateway",
            "2001:db8::10".parse().unwrap(),
            "2001:db8:1::1".parse().unwrap(),
            Some("fe80::1".parse().unwrap()),
        ),
    ];

    for (case, source, destination, gateway) in cases {
        let mut decision = route(gateway);
        decision.selected_address = Some(source);
        decision.preferred_source = Some(source);
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::new()));
        let plan = RoutePlanner
            .plan(
                &packet,
                Some(destination),
                &PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(decision),
            )
            .unwrap();

        assert_eq!(
            plan.neighbor_target,
            Some(gateway.unwrap_or(destination)),
            "{case}"
        );
        assert!(plan.destination_mac.is_none(), "{case}");
    }
}

#[test]
fn materialization_uses_interface_identity_and_retains_resolution_evidence() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = Ipv4Addr::new(198, 51, 100, 1);
    let spoofed_ip = Ipv4Addr::new(203, 0, 113, 99);
    let spoofed_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let resolved_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
    let captured = Frame::new(
        std::time::SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        Bytes::from_static(&[0; 14]),
    )
    .unwrap();
    let resolution = NeighborResolution {
        mac_address: resolved_mac,
        attempts: 2,
        cache_hit: false,
        captured: vec![captured],
        evidence_truncated: true,
        capture_statistics: CaptureStatistics {
            received_frames: 2,
            received_bytes: 120,
            ..CaptureStatistics::default()
        },
    };
    let resolver = RecordingResolver {
        request: Mutex::new(None),
        resolution: resolution.clone(),
    };
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            source: spoofed_mac,
            ..Ethernet::default()
        })
        .push(Vlan8021ad {
            priority: 5,
            vlan_id: 100,
            ..Vlan8021ad::default()
        })
        .push(Vlan {
            priority: 1,
            drop_eligible: true,
            vlan_id: 200,
            ..Vlan::default()
        })
        .push(Ipv4 {
            source: spoofed_ip,
            destination,
            ..Ipv4::default()
        });

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route(Some(gateway))),
        )
        .unwrap();
    assert_eq!(plan.packet_source, Some(IpAddr::V4(spoofed_ip)));
    assert_eq!(plan.source_mac, Some(MacAddress(spoofed_mac)));

    let materialized = RoutePlanner.materialize(plan, &resolver).unwrap();
    assert_eq!(materialized.plan.destination_mac, Some(resolved_mac));
    assert_eq!(materialized.neighbor_resolution, Some(resolution));
    assert_eq!(
        *resolver.request.lock().unwrap(),
        Some(NeighborRequest {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            interface_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: gateway,
            vlan_tags: vec![
                NeighborVlanTag {
                    kind: NeighborVlanKind::Ieee8021Ad,
                    priority: 5,
                    drop_eligible: false,
                    vlan_id: 100,
                },
                NeighborVlanTag {
                    kind: NeighborVlanKind::Ieee8021Q,
                    priority: 1,
                    drop_eligible: true,
                    vlan_id: 200,
                },
            ],
            mtu: 1500,
            link_type: LinkType::ETHERNET,
        })
    );
}

#[test]
fn fully_specified_layer2_frame_needs_no_neighbor_source() {
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let mut packet = Packet::new();
    packet
        .push(packetcraftr_protocol::link::Ethernet {
            source: [2, 0, 0, 0, 0, 1],
            destination: [2, 0, 0, 0, 0, 2],
            ..packetcraftr_protocol::link::Ethernet::default()
        })
        .push(Raw::new(Bytes::from_static(b"frame")));
    let route = RouteDecision {
        selected_address: None,
        preferred_source: None,
        source_mac: None,
        ..route(None)
    };

    let plan = RoutePlanner
        .plan(
            &packet,
            Some(destination),
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route),
        )
        .unwrap();

    assert_eq!(plan.neighbor_source, None);
    assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
    assert_eq!(plan.destination_mac, Some(MacAddress([2, 0, 0, 0, 0, 2])));
}

#[test]
fn destination_free_custom_ethernet_uses_only_interface_lookup() {
    let mut packet = Packet::new();
    packet
        .push(packetcraftr_protocol::link::Ethernet {
            source: [2, 0, 0, 0, 0, 1],
            destination: [2, 0, 0, 0, 0, 2],
            ether_type: WireValue::Exact(0x88b5),
        })
        .push(Raw::new(Bytes::from_static(b"custom")));
    let decision = RouteDecision {
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        ..route(None)
    };
    let interface = decision.interface.clone();
    let provider = InterfaceOnlyRoute::new(decision);

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Auto,
                interface: Some(interface),
                preferred_source: None,
            },
            &provider,
        )
        .unwrap();

    assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(provider.interface_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(plan.lookup_destination, None);
    assert_eq!(plan.final_destination, None);
    assert!(plan.visited_destinations.is_empty());
    assert_eq!(plan.destination_mac, Some(MacAddress([2, 0, 0, 0, 0, 2])));
    assert!(!plan.needs_neighbor_resolution());
    RoutePlanner.materialize(plan, &NeverResolve).unwrap();
}

#[test]
fn destination_free_layer2_requires_explicit_interface() {
    let mut packet = Packet::new();
    packet.push(packetcraftr_protocol::link::Ethernet {
        source: [2, 0, 0, 0, 0, 1],
        destination: [2, 0, 0, 0, 0, 2],
        ether_type: WireValue::Exact(0x88b5),
    });
    let provider = InterfaceOnlyRoute::new(route(None));

    let error = RoutePlanner
        .plan(&packet, None, &PlanOptions::default(), &provider)
        .unwrap_err();

    assert!(matches!(error, PlanError::MissingLayer2Interface));
    assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(provider.interface_lookups.load(Ordering::SeqCst), 0);
}

#[test]
fn complete_arp_synthesizes_broadcast_envelope_without_ip_route() {
    let mut packet = Packet::new();
    packet.push(packetcraftr_protocol::link::Arp {
        sender_hardware: [2, 0, 0, 0, 0, 1],
        sender_protocol: Ipv4Addr::new(192, 0, 2, 10),
        target_protocol: Ipv4Addr::new(192, 0, 2, 20),
        ..packetcraftr_protocol::link::Arp::default()
    });
    let decision = RouteDecision {
        source_mac: None,
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        ..route(None)
    };
    let interface = decision.interface.clone();
    let provider = InterfaceOnlyRoute::new(decision);

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: Some(interface),
                preferred_source: None,
            },
            &provider,
        )
        .unwrap();

    assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(plan.destination_mac, Some(MacAddress([0xff; 6])));
    assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
    assert!(plan.synthesized_ethernet);
    assert!(!plan.needs_neighbor_resolution());
    RoutePlanner.materialize(plan, &NeverResolve).unwrap();
}

#[test]
fn externally_constructed_invalid_plan_returns_typed_error() {
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::new()));
    let mut plan = RoutePlanner
        .plan(
            &packet,
            Some(destination),
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route(None)),
        )
        .unwrap();
    plan.neighbor_target = None;
    plan.destination_mac = None;

    assert_eq!(
        RoutePlanner.materialize(plan, &NeverResolve).unwrap_err(),
        NeighborError::MissingNeighborTarget {
            interface: "test0".to_owned()
        }
    );
}
