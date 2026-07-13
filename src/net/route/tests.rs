#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use bytes::Bytes;

    use super::*;
    use crate::packet::internal::{Raw, WireValue};
    use crate::protocol::internal::{Ethernet, Ipv4, Ipv6, SegmentRoutingHeader, Vlan, Vlan8021ad};

    struct FixedRoute(RouteDecision);

    impl RouteProvider for FixedRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct PreferenceAwareRoute;

    impl RouteProvider for PreferenceAwareRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            Ok(route(None))
        }

        fn lookup_with_preferences(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
            preferred_source: Option<IpAddr>,
        ) -> Result<RouteDecision, Self::Error> {
            let mut decision = route(None);
            if let Some(preferred_source) = preferred_source {
                decision.selected_address = Some(preferred_source);
                decision.preferred_source = Some(preferred_source);
            }
            Ok(decision)
        }
    }

    struct InterfaceOnlyRoute {
        decision: RouteDecision,
        ip_lookups: AtomicUsize,
        interface_lookups: AtomicUsize,
    }

    impl InterfaceOnlyRoute {
        fn new(decision: RouteDecision) -> Self {
            Self {
                decision,
                ip_lookups: AtomicUsize::new(0),
                interface_lookups: AtomicUsize::new(0),
            }
        }
    }

    impl RouteProvider for InterfaceOnlyRoute {
        type Error = Infallible;

        fn lookup(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
        ) -> Result<RouteDecision, Self::Error> {
            self.ip_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        fn lookup_interface(
            &self,
            _interface: &InterfaceId,
        ) -> Result<Option<RouteDecision>, Self::Error> {
            self.interface_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.decision.clone()))
        }
    }

    struct NeverResolve;

    impl NeighborResolver for NeverResolve {
        fn resolve(
            &self,
            _interface: &InterfaceId,
            _interface_source: IpAddr,
            _target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            unreachable!("invalid plan must fail before calling the resolver")
        }
    }

    struct RecordingResolver {
        request: Mutex<Option<NeighborRequest>>,
        resolution: NeighborResolution,
    }

    impl NeighborResolver for RecordingResolver {
        fn resolve(
            &self,
            _interface: &InterfaceId,
            _interface_source: IpAddr,
            _target: IpAddr,
        ) -> Result<MacAddress, NeighborError> {
            unreachable!("rich neighbor context must be used during materialization")
        }

        fn resolve_request(
            &self,
            request: &NeighborRequest,
        ) -> Result<NeighborResolution, NeighborError> {
            *self.request.lock().unwrap() = Some(request.clone());
            Ok(self.resolution.clone())
        }
    }

    fn route(next_hop: Option<IpAddr>) -> RouteDecision {
        RouteDecision {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            next_hop,
            selection_reason: if next_hop.is_some() {
                RouteSelectionReason::Gateway
            } else {
                RouteSelectionReason::OnLink
            },
            destination_scope: DestinationScope::Global,
            mtu: 1500,
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
        let network_layer = || Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 10),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        };

        let mut ethernet = Packet::new();
        ethernet.push(Ethernet::default()).push(network_layer());

        let mut customer_vlan_root = Packet::new();
        customer_vlan_root
            .push(Vlan::default())
            .push(network_layer());

        let mut service_vlan_root = Packet::new();
        service_vlan_root
            .push(Vlan8021ad::default())
            .push(network_layer());

        let mut ethernet_stacked = Packet::new();
        ethernet_stacked
            .push(Ethernet::default())
            .push(Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(network_layer());

        let mut vlan_rooted_stacked = Packet::new();
        vlan_rooted_stacked
            .push(Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(network_layer());

        // This deliberately unusual order proves canonical link intent wins
        // over the otherwise Layer 3-capable IP-root Auto branch.
        let mut ip_root_with_service_vlan = Packet::new();
        ip_root_with_service_vlan
            .push(network_layer())
            .push(Vlan8021ad::default());

        vec![
            ("ethernet", ethernet),
            ("vlan", customer_vlan_root),
            ("vlan8021ad", service_vlan_root),
            ("ethernet-stacked-vlan", ethernet_stacked),
            ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
            ("ip-root-with-service-vlan", ip_root_with_service_vlan),
        ]
    }

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
    fn legacy_injected_provider_rejects_an_unhonored_source_preference() {
        let preferred_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 99),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        });

        let error = RoutePlanner
            .plan(
                &packet,
                None,
                &PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: Some(preferred_source),
                },
                &FixedRoute(route(None)),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            PlanError::PreferredSourceNotSelected {
                requested,
                selected: Some(selected),
            } if requested == preferred_source
                && selected == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        ));
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
            SystemRouteProvider.lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None),
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
            .push(crate::protocol::internal::Ethernet {
                source: [2, 0, 0, 0, 0, 1],
                destination: [2, 0, 0, 0, 0, 2],
                ..crate::protocol::internal::Ethernet::default()
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
            .push(crate::protocol::internal::Ethernet {
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
        packet.push(crate::protocol::internal::Ethernet {
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
        packet.push(crate::protocol::internal::Arp {
            sender_hardware: [2, 0, 0, 0, 0, 1],
            sender_protocol: Ipv4Addr::new(192, 0, 2, 10),
            target_protocol: Ipv4Addr::new(192, 0, 2, 20),
            ..crate::protocol::internal::Arp::default()
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
}
