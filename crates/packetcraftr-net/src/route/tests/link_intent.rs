// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Arp, Ethernet, FixedRoute, InterfaceOnlyRoute, IpAddr, Ipv4, Ipv4Addr, Ipv6Addr,
    LinkCapability, LinkMode, LinkType, MacAddress, Ordering, Packet, PlanError, PlanOptions,
    PreferenceAwareRoute, RouteDecision, RoutePlanner, Udp, Vlan, Vxlan, WireValue,
    canonical_link_intent_packets, route,
};
#[cfg(not(feature = "native-route"))]
use super::{NativeRouteError, RouteProvider, SystemRouteProvider};

#[test]
fn explicit_layer3_rejects_every_canonical_link_intent_before_route_lookup() {
    for (case, packet) in canonical_link_intent_packets() {
        let provider = InterfaceOnlyRoute::new(route(None));
        let error = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                &provider,
            )
            .unwrap_err();

        assert!(matches!(error, PlanError::EthernetInLayer3), "{case}");
        assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0, "{case}");
        assert_eq!(
            provider.interface_lookups.load(Ordering::SeqCst),
            0,
            "{case}"
        );
    }
}

fn vxlan_tunneled_frame_packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 10),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 4789,
            ..Udp::default()
        })
        .push(Vxlan::default())
        .push(Ethernet {
            destination: [9; 6],
            source: [8; 6],
            ether_type: WireValue::Auto,
        })
        .push(Vlan {
            vlan_id: 300,
            ..Vlan::default()
        })
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 168, 1, 1),
            destination: Ipv4Addr::new(192, 168, 1, 5),
            ..Ipv4::default()
        });
    packet
}

#[test]
fn a_tunneled_ethernet_frame_carries_no_outer_link_intent() {
    let packet = vxlan_tunneled_frame_packet();
    let provider = FixedRoute(route(None));

    let explicit = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
            &provider,
        )
        .unwrap();
    assert_eq!(explicit.mode, LinkMode::Layer3);

    let auto = RoutePlanner
        .plan(&packet, None, &PlanOptions::default(), &provider)
        .unwrap();
    assert_eq!(auto.mode, LinkMode::Layer3);
}

#[test]
fn layer2_planning_ignores_addresses_inside_the_tunneled_frame() {
    let packet = vxlan_tunneled_frame_packet();
    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
            &FixedRoute(route(None)),
        )
        .unwrap();

    // The tunneled frame's MACs and VLAN tag describe the encapsulated
    // network: the outer link still needs synthesis, neighbor resolution,
    // and an untagged neighbor probe.
    assert!(plan.synthesized_ethernet);
    assert!(plan.destination_mac.is_none());
    assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
    assert!(plan.neighbor_vlan_tags.is_empty());
    assert!(plan.neighbor_target.is_some());
}

#[test]
fn a_tunneled_arp_payload_lends_no_macs_to_the_outer_link() {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 10),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 49152,
            destination_port: 4789,
            ..Udp::default()
        })
        .push(Vxlan::default())
        .push(Ethernet::default())
        .push(Arp {
            operation: 2,
            sender_hardware: [7; 6],
            target_hardware: [6; 6],
            ..Arp::default()
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
            &FixedRoute(route(None)),
        )
        .unwrap();

    assert!(plan.destination_mac.is_none());
    assert_eq!(plan.source_mac, Some(MacAddress([2, 0, 0, 0, 0, 1])));
}

#[test]
fn auto_selects_layer2_for_canonical_single_and_stacked_link_intent() {
    for (case, packet) in canonical_link_intent_packets() {
        let protocol_ids = packet
            .iter()
            .map(|layer| layer.protocol_id().to_string())
            .collect::<Vec<_>>();
        assert!(
            protocol_ids.iter().any(|protocol| {
                matches!(protocol.as_str(), "ethernet" | "vlan" | "vlan8021ad")
            }),
            "{case}: {protocol_ids:?}"
        );

        let plan = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions::default(),
                &FixedRoute(route(None)),
            )
            .unwrap();

        assert_eq!(plan.mode, LinkMode::Layer2, "{case}: {protocol_ids:?}");
    }
}

#[test]
fn injected_provider_can_honor_a_source_preference() {
    let preferred_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 99),
        destination: Ipv4Addr::new(198, 51, 100, 1),
        ..Ipv4::default()
    });

    let plan = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: Some(preferred_source),
            },
            &PreferenceAwareRoute,
        )
        .unwrap();

    assert_eq!(plan.route.selected_address, Some(preferred_source));
    assert_eq!(plan.route.preferred_source, Some(preferred_source));
}

#[test]
fn preferred_source_family_is_rejected_before_provider_lookup() {
    let provider = InterfaceOnlyRoute::new(route(None));
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: Ipv4Addr::new(198, 51, 100, 1),
        ..Ipv4::default()
    });
    let preferred_source = IpAddr::V6(Ipv6Addr::LOCALHOST);

    let error = RoutePlanner
        .plan(
            &packet,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: Some(preferred_source),
            },
            &provider,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PlanError::PreferredSourceFamilyMismatch {
            preferred_source: actual,
            destination,
        } if actual == preferred_source
            && destination == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
    ));
    assert_eq!(provider.ip_lookups.load(Ordering::SeqCst), 0);
}

#[cfg(not(feature = "native-route"))]
#[test]
fn system_route_provider_reports_the_feature_boundary() {
    assert!(matches!(
        SystemRouteProvider.lookup_with_preferences(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            None,
        ),
        Err(NativeRouteError::Unsupported { message })
            if message.contains("native-route")
    ));
}

#[test]
fn auto_link_intent_does_not_fall_back_when_layer2_is_unsupported() {
    let packet = canonical_link_intent_packets()
        .into_iter()
        .find_map(|(case, packet)| (case == "vlan8021ad").then_some(packet))
        .unwrap();
    let decision = RouteDecision {
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV4,
        ..route(None)
    };

    for link_mode in [LinkMode::Auto, LinkMode::Layer2] {
        let error = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode,
                    interface: None,
                    preferred_source: None,
                },
                &FixedRoute(decision.clone()),
            )
            .unwrap_err();

        assert!(
            matches!(error, PlanError::Layer2Unsupported),
            "{link_mode:?}"
        );
    }
}
