// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Bytes, CaptureStatistics, FixedRoute, IpAddr, Ipv4, Ipv4Addr, Ipv6, Ipv6Addr, LinkCapability,
    LinkMode, LinkType, MacAddress, Mutex, NeighborResolution, Packet, PlanError, PlanOptions,
    RecordingResolver, RouteDecision, RoutePlanner, SegmentRoutingHeader, WireValue, route,
};

#[test]
fn srh_route_lookup_uses_the_current_active_segment() {
    let source: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let first: std::net::Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: std::net::Ipv6Addr = "2001:db8::20".parse().unwrap();
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source,
            destination: final_destination,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![first, final_destination],
            segments_left: WireValue::Raw(Bytes::from_static(&[0])),
            ..SegmentRoutingHeader::default()
        });
    let decision = RouteDecision {
        selected_address: Some(IpAddr::V6(source)),
        preferred_source: Some(IpAddr::V6(source)),
        next_hop: None,
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV6,
        ..route(None)
    };
    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(decision),
        )
        .unwrap();
    assert_eq!(plan.lookup_destination, Some(IpAddr::V6(final_destination)));
    assert_eq!(
        plan.visited_destinations,
        vec![IpAddr::V6(final_destination)]
    );
}

#[test]
fn srh_route_distinguishes_active_and_final_destinations() {
    let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let active: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source,
            destination: active,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![active, final_destination],
            ..SegmentRoutingHeader::default()
        });
    let decision = RouteDecision {
        selected_address: Some(IpAddr::V6(source)),
        preferred_source: Some(IpAddr::V6(source)),
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV6,
        ..route(None)
    };

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(decision),
        )
        .unwrap();

    assert_eq!(plan.lookup_destination, Some(IpAddr::V6(active)));
    assert_eq!(plan.final_destination, Some(IpAddr::V6(final_destination)));
    assert_eq!(
        plan.visited_destinations,
        vec![IpAddr::V6(active), IpAddr::V6(final_destination)]
    );
}

#[test]
fn ipv4_source_route_uses_only_unvisited_option_destinations() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let active = Ipv4Addr::new(10, 0, 0, 2);
    let visited = Ipv4Addr::new(10, 0, 0, 3);
    let final_destination = Ipv4Addr::new(10, 0, 0, 4);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination: active,
        options: Bytes::from(
            [131, 11, 8]
                .into_iter()
                .chain(visited.octets())
                .chain(final_destination.octets())
                .collect::<Vec<_>>(),
        ),
        ..Ipv4::default()
    });
    let decision = RouteDecision {
        selected_address: Some(IpAddr::V4(source)),
        preferred_source: Some(IpAddr::V4(source)),
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV4,
        ..route(None)
    };

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(decision),
        )
        .unwrap();

    assert_eq!(plan.lookup_destination, Some(IpAddr::V4(active)));
    assert_eq!(plan.final_destination, Some(IpAddr::V4(final_destination)));
    assert_eq!(
        plan.visited_destinations,
        vec![IpAddr::V4(active), IpAddr::V4(final_destination)]
    );
}

#[test]
fn ipv4_source_route_requires_an_explicit_active_header_destination() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let active = Ipv4Addr::new(10, 0, 0, 2);
    let final_destination = Ipv4Addr::new(10, 0, 0, 3);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination: Ipv4Addr::UNSPECIFIED,
        options: Bytes::from(
            [131, 11, 4]
                .into_iter()
                .chain(active.octets())
                .chain(final_destination.octets())
                .collect::<Vec<_>>(),
        ),
        ..Ipv4::default()
    });

    let error = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route(None)),
        )
        .unwrap_err();

    assert!(matches!(error, PlanError::InvalidSourceRouting { .. }));
}

#[test]
fn malformed_ipv4_options_are_invalid_source_routing() {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        options: Bytes::from_static(&[131, 2]),
        ..Ipv4::default()
    });

    let error = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route(None)),
        )
        .unwrap_err();

    assert!(matches!(error, PlanError::InvalidSourceRouting { .. }));
}

#[test]
fn encapsulated_srh_does_not_redirect_the_outer_route() {
    let outer_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let inner_segment: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: "2001:db8:1::1".parse().unwrap(),
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![inner_segment, inner_destination],
            segments_left: WireValue::Raw(Bytes::from_static(&[1])),
            ..SegmentRoutingHeader::default()
        });
    let decision = RouteDecision {
        selected_address: Some(IpAddr::V6(outer_source)),
        preferred_source: Some(IpAddr::V6(outer_source)),
        next_hop: None,
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV6,
        ..route(None)
    };

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(decision),
        )
        .unwrap();

    assert_eq!(plan.lookup_destination, Some(IpAddr::V6(outer_destination)));
    assert_eq!(plan.final_destination, Some(IpAddr::V6(outer_destination)));
    assert_eq!(
        plan.visited_destinations,
        vec![IpAddr::V6(outer_destination)]
    );
}

#[test]
fn mixed_family_encapsulation_materializes_against_the_outer_envelope() {
    let outer_source = Ipv4Addr::new(192, 0, 2, 10);
    let outer_destination = Ipv4Addr::new(198, 51, 100, 50);
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let inner_source: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let resolved_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        });

    let resolution = NeighborResolution {
        mac_address: resolved_mac,
        attempts: 1,
        cache_hit: true,
        captured: Vec::new(),
        evidence_truncated: false,
        capture_statistics: CaptureStatistics::default(),
    };
    let resolver = RecordingResolver {
        request: Mutex::new(None),
        resolution: resolution.clone(),
    };
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

    assert_eq!(plan.lookup_destination, Some(IpAddr::V4(outer_destination)));
    assert_eq!(plan.final_destination, Some(IpAddr::V4(outer_destination)));
    assert_eq!(
        plan.visited_destinations,
        vec![IpAddr::V4(outer_destination)]
    );
    assert_eq!(plan.packet_source, Some(IpAddr::V4(outer_source)));
    assert_eq!(plan.neighbor_source, Some(IpAddr::V4(outer_source)));
    assert_eq!(plan.neighbor_target, Some(gateway));

    let materialized = RoutePlanner.materialize(plan, &resolver).unwrap();
    assert_eq!(materialized.plan.destination_mac, Some(resolved_mac));
    assert_eq!(materialized.neighbor_resolution, Some(resolution));
    assert_eq!(
        resolver.request.lock().unwrap().as_ref().map(|request| (
            request.interface_source,
            request.target,
            request.link_type
        )),
        Some((IpAddr::V4(outer_source), gateway, LinkType::ETHERNET))
    );
}

#[test]
fn unspecified_outer_ip_does_not_route_to_an_explicit_inner_destination() {
    let requested_destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let inner_destination = Ipv4Addr::new(10, 0, 0, 99);
    let mut packet = Packet::new();
    packet.push(Ipv4::default()).push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: inner_destination,
        ..Ipv4::default()
    });

    let plan = RoutePlanner
        .plan(
            &packet,
            Some(requested_destination),
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(RouteDecision {
                capability: LinkCapability::Layer3,
                link_type: LinkType::IPV4,
                ..route(None)
            }),
        )
        .unwrap();

    assert_eq!(plan.lookup_destination, Some(requested_destination));
    assert_eq!(plan.final_destination, Some(requested_destination));
    assert_eq!(plan.visited_destinations, vec![requested_destination]);
}
