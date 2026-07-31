// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn raw_ipv4(destination: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![0_u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&20_u16.to_be_bytes());
    bytes[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes
}

fn raw_ethernet_request(payload: Vec<u8>, ether_type: u16, vlan: bool) -> Packet {
    let mut request = Packet::new();
    request.push(Ethernet {
        destination: [0; 6],
        source: [0; 6],
        ether_type: WireValue::Exact(if vlan { 0x8100 } else { ether_type }),
    });
    if vlan {
        request.push(Vlan {
            vlan_id: 42,
            ether_type: WireValue::Exact(ether_type),
            ..Vlan::default()
        });
    }
    request.push(Raw::new(Bytes::from(payload)));
    request
}

fn permissive_layer2_options() -> SendOptions {
    SendOptions {
        destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        plan: PlanOptions {
            link_mode: LinkMode::Layer2,
            ..PlanOptions::default()
        },
        build: BuildOptions {
            mode: packetcraftr_packet::build::BuildMode::Permissive,
            ..BuildOptions::default()
        },
        allow_permissive_live: true,
    }
}

#[test]
fn temporary_malformed_gre_can_hide_public_destination() {
    let neighbors = CountingNeighbors::default();
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors,
        io.clone(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );

    let mut outer = raw_ipv4(Ipv4Addr::new(10, 0, 0, 2));
    outer[2..4].copy_from_slice(&44_u16.to_be_bytes());
    outer[9] = 47;
    outer.extend_from_slice(&[0, 1, 0x08, 0]); // unsupported GRE version, IPv4 payload
    outer.extend_from_slice(&raw_ipv4(Ipv4Addr::new(8, 8, 8, 8)));

    assert!(
        client
            .send(
                raw_ethernet_request(outer, 0x0800, false),
                permissive_layer2_options(),
            )
            .is_ok()
    );
    assert!(!io.0.lock().unwrap().is_empty());
}

#[test]
fn mapped_private_ipv4_destination_is_not_treated_as_public_ipv6() {
    let destination = "::ffff:10.0.0.2".parse().unwrap();
    let mut request = Packet::new();
    request.push(Ipv6 {
        source: "::ffff:10.0.0.1".parse().unwrap(),
        destination,
        ..Ipv6::default()
    });
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            selected_address: Some(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())),
            preferred_source: Some(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())),
            link_type: LinkType::IPV6,
            ..route(LinkCapability::Layer3)
        }),
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );

    client
        .plan(&request, None, &PlanOptions::default())
        .unwrap();
}

#[test]
fn materialized_packet_destinations_are_authorized() {
    let registry = Arc::new(default_registry().unwrap());
    let client = Client::new(
        Arc::clone(&registry),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );
    let mut built = Builder::new(registry)
        .build(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12_345,
                9,
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    built.packet.get_mut::<Ipv4>().unwrap().destination = Ipv4Addr::new(8, 8, 8, 8);

    assert!(matches!(
        client.authorize_built(&built, false),
        Err(ClientError::Policy(
            TrafficPolicyError::PublicDestination { destination }
        )) if destination == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));
}

#[test]
fn exact_wire_authorization_rejects_hidden_or_malformed_destinations() {
    let neighbors = CountingNeighbors::default();
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        io.clone(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );

    for vlan in [false, true] {
        assert!(matches!(
            client.send(
                raw_ethernet_request(raw_ipv4(Ipv4Addr::new(8, 8, 8, 8)), 0x0800, vlan),
                permissive_layer2_options(),
            ),
            Err(ClientError::Policy(
                TrafficPolicyError::PublicDestination { .. }
            ))
        ));
    }
    assert!(matches!(
        client.send(
            raw_ethernet_request(vec![0x45; 19], 0x0800, false),
            permissive_layer2_options(),
        ),
        Err(ClientError::Policy(
            TrafficPolicyError::InvalidPacketSemantics { .. }
        ))
    ));
    let mut unsupported_routing = vec![0_u8; 48];
    unsupported_routing[0] = 0x60;
    unsupported_routing[4..6].copy_from_slice(&8_u16.to_be_bytes());
    unsupported_routing[6] = 43;
    unsupported_routing[7] = 64;
    unsupported_routing[8..24]
        .copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    unsupported_routing[24..40]
        .copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    unsupported_routing[40] = 59;
    unsupported_routing[42] = u8::MAX;
    unsupported_routing[43] = 1;
    assert!(matches!(
        client.send(
            raw_ethernet_request(unsupported_routing, 0x86dd, false),
            permissive_layer2_options(),
        ),
        Err(ClientError::Policy(
            TrafficPolicyError::InvalidPacketSemantics { .. }
        ))
    ));
    let mut fragmented = vec![0_u8; 48];
    fragmented[0] = 0x60;
    fragmented[4..6].copy_from_slice(&8_u16.to_be_bytes());
    fragmented[6] = 44;
    fragmented[7] = 64;
    fragmented[8..24].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    fragmented[24..40].copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    fragmented[40] = 43;
    fragmented[42..44].copy_from_slice(&8_u16.to_be_bytes());
    assert!(matches!(
        client.send(
            raw_ethernet_request(fragmented, 0x86dd, false),
            permissive_layer2_options(),
        ),
        Err(ClientError::Policy(
            TrafficPolicyError::InvalidPacketSemantics { .. }
        ))
    ));
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert!(io.0.lock().unwrap().is_empty());
}

#[test]
fn custom_registry_cannot_hide_a_wire_destination() {
    let mut builder = RegistryBuilder::new();
    builder.register_codec(MacSensitiveCodec).unwrap();
    builder
        .bind_link_type(LinkType::RAW.0, "test.mac_sensitive")
        .unwrap();
    let neighbors = CountingNeighbors::default();
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(builder.build().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer3,
            link_type: LinkType::RAW,
            ..route(LinkCapability::Layer3)
        }),
        neighbors.clone(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let mut request = Packet::new();
    request.push(MacSensitiveLayer(Some(Bytes::from(raw_ipv4(
        Ipv4Addr::new(8, 8, 8, 8),
    )))));

    assert!(matches!(
        client.send(
            request,
            SendOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    ..PlanOptions::default()
                },
                ..SendOptions::default()
            },
        ),
        Err(ClientError::Policy(
            TrafficPolicyError::PublicDestination { .. }
        ))
    ));
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert!(io.0.lock().unwrap().is_empty());
}

#[test]
fn synthesized_ethernet_is_authorized_before_neighbor_traffic() {
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        RejectingPacketIo,
        TrafficPolicy {
            max_bytes_per_operation: 28,
            ..TrafficPolicy::default()
        },
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Policy(TrafficPolicyError::ByteLimit {
            actual: 42,
            limit: 28
        })
    ));
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
}

#[test]
fn mtu_uses_actual_network_span_even_for_permissive_lengths() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        RecordingIo::default(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let mut request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    request.push(packetcraftr_packet::layer::Raw::new(vec![0_u8; 2_000]));
    request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(20);
    let error = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                build: BuildOptions {
                    mode: packetcraftr_packet::build::BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                allow_permissive_live: true,
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::PacketExceedsMtu { actual, mtu: 1500 } if actual > 2_000
    ));
}

#[test]
fn arp_target_is_authorized_before_route_lookup() {
    let target = Ipv4Addr::new(8, 8, 8, 8);
    let mut request = Packet::new();
    request.push(Arp {
        sender_protocol: Ipv4Addr::new(10, 0, 0, 1),
        target_protocol: target,
        ..Arp::default()
    });
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer2),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );

    assert!(matches!(
        client.plan(&request, None, &PlanOptions::default()),
        Err(ClientError::Policy(
            TrafficPolicyError::PublicDestination { destination }
        )) if destination == IpAddr::V4(target)
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_route_bearing_custom_layer_fails_closed_before_route_lookup() {
    let mut request = Packet::new();
    request.push(CustomRouteLayer);
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );

    assert!(matches!(
        client.plan(&request, None, &PlanOptions::default()),
        Err(ClientError::Policy(TrafficPolicyError::InvalidPacketSemantics { reason }))
            if reason.contains("test.custom_route") && reason.contains("destination")
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn srh_policy_checks_final_segment_not_only_first_hop() {
    let source: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let first: std::net::Ipv6Addr = "fd00::10".parse().unwrap();
    let final_destination: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source,
            destination: first,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![first, final_destination],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp::default());
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: RouteDecision {
                selected_address: Some(IpAddr::V6(source)),
                preferred_source: Some(IpAddr::V6(source)),
                next_hop: None,
                capability: LinkCapability::Layer3,
                link_type: LinkType::IPV6,
                ..route(LinkCapability::Layer3)
            },
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );

    let error = client
        .plan(
            &request,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Policy(TrafficPolicyError::PublicDestination { destination })
            if destination == IpAddr::V6(final_destination)
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn ipv4_source_routes_and_multicast_are_authorized_before_route_lookup() {
    for option_type in [131, 137] {
        let route_calls = Arc::new(AtomicUsize::new(0));
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12_345,
            9,
        );
        request.get_mut::<Ipv4>().unwrap().options =
            Bytes::from(vec![option_type, 7, 4, 8, 8, 8, 8]);
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            CountingRoutes {
                decision: route(LinkCapability::Layer3),
                calls: Arc::clone(&route_calls),
            },
            CountingNeighbors::default(),
            RejectingPacketIo,
            TrafficPolicy::default(),
        );
        assert!(matches!(
            client.plan(&request, None, &PlanOptions::default()),
            Err(ClientError::Policy(
                TrafficPolicyError::PublicDestination { destination }
            )) if destination == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
        assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    }

    for malformed in [
        vec![131, 6, 4, 10, 0, 0],
        vec![137, 7, 3, 10, 0, 0, 1],
        vec![131, 7, 4, 10, 0],
    ] {
        let route_calls = Arc::new(AtomicUsize::new(0));
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12_345,
            9,
        );
        request.get_mut::<Ipv4>().unwrap().options = Bytes::from(malformed);
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            CountingRoutes {
                decision: route(LinkCapability::Layer3),
                calls: Arc::clone(&route_calls),
            },
            CountingNeighbors::default(),
            RejectingPacketIo,
            TrafficPolicy::default(),
        );
        assert!(matches!(
            client.plan(&request, None, &PlanOptions::default()),
            Err(ClientError::Policy(
                TrafficPolicyError::InvalidPacketSemantics { .. }
            ))
        ));
        assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    }

    let policy = TrafficPolicy::default();
    for destination in [
        IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
        IpAddr::V6("ff0e::1234".parse().unwrap()),
    ] {
        assert_eq!(
            policy.authorize_destination(destination),
            Err(TrafficPolicyError::PublicDestination { destination })
        );
    }
    let permissive = TrafficPolicy {
        allow_public_destinations: true,
        ..TrafficPolicy::default()
    };
    assert!(
        permissive
            .authorize_destination(IpAddr::V6("ff0e::1234".parse().unwrap()))
            .is_ok()
    );
}

#[test]
fn exchange_accounts_generated_template_packets_lazily() {
    let generated = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&generated);
    let mut base = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    base.push(packetcraftr_packet::layer::Raw::default());
    let template = PacketTemplate::new(base).axis(
        2,
        "bytes",
        TemplateValues::Generated {
            count: 100,
            generator: Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                FieldValue::Bytes(Bytes::from(vec![0_u8; 1024]))
            }),
        },
    );
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy {
            max_bytes_per_operation: 2_200,
            ..TrafficPolicy::default()
        },
    );

    assert!(matches!(
        client.exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        ),
        Err(ClientError::Policy(TrafficPolicyError::ByteLimit { .. }))
    ));
    assert!(generated.load(Ordering::SeqCst) <= 3);
}
