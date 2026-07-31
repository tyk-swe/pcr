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

fn raw_ipv6(destination: std::net::Ipv6Addr) -> Vec<u8> {
    let mut bytes = vec![0_u8; 40];
    bytes[0] = 0x60;
    bytes[6] = 59;
    bytes[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    bytes[24..40].copy_from_slice(&destination.octets());
    bytes
}

fn raw_ethernet_request(ether_type: u16, payload: Vec<u8>, vlan: bool) -> Packet {
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
            interface: None,
            preferred_source: None,
        },
        build: BuildOptions {
            mode: packetcraftr_packet::build::BuildMode::Permissive,
            ..BuildOptions::default()
        },
        allow_permissive_live: true,
    }
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
fn permissive_raw_ethernet_and_vlan_cannot_hide_public_ipv4() {
    for vlan in [false, true] {
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
        let error = client
            .send(
                raw_ethernet_request(0x0800, raw_ipv4(Ipv4Addr::new(8, 8, 8, 8)), vlan),
                permissive_layer2_options(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::Policy(TrafficPolicyError::PublicDestination { destination })
                if destination == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
        assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
        assert!(io.0.lock().unwrap().is_empty());
    }
}

#[test]
fn private_raw_vlan_is_authorized_as_the_exact_transmitted_bytes() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let report = client
        .send(
            raw_ethernet_request(0x0800, raw_ipv4(Ipv4Addr::new(10, 0, 0, 2)), true),
            permissive_layer2_options(),
        )
        .unwrap();
    assert_eq!(
        io.0.lock().unwrap().as_slice(),
        std::slice::from_ref(&report.built.bytes)
    );
    assert_eq!(report.wire_bytes, report.built.bytes);
}

#[test]
fn permissive_raw_ethernet_rejects_global_ipv6_and_truncated_ip() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let global: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    let global_error = client
        .send(
            raw_ethernet_request(0x86dd, raw_ipv6(global), false),
            permissive_layer2_options(),
        )
        .unwrap_err();
    assert!(
        matches!(
            global_error,
            ClientError::Policy(
                TrafficPolicyError::PublicDestination {
                    destination: IpAddr::V6(destination)
                }
            ) if destination == global
        ),
        "{global_error:?}"
    );
    assert!(matches!(
        client.send(
            raw_ethernet_request(0x0800, vec![0x45; 19], false),
            permissive_layer2_options(),
        ),
        Err(ClientError::Policy(
            TrafficPolicyError::InvalidPacketSemantics { .. }
        ))
    ));
}

#[test]
fn exact_wire_policy_denial_happens_before_exchange_capture() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let error = client
        .exchange(
            &PacketTemplate::new(raw_ethernet_request(
                0x0800,
                raw_ipv4(Ipv4Addr::new(8, 8, 8, 8)),
                true,
            )),
            ExchangeOptions {
                send: permissive_layer2_options(),
                ..ExchangeOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Policy(TrafficPolicyError::PublicDestination { .. })
    ));
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn unknown_raw_ether_type_has_no_route_bearing_destination() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let report = client
        .send(
            raw_ethernet_request(0x88b5, vec![1, 2, 3, 4], false),
            permissive_layer2_options(),
        )
        .unwrap();
    assert_eq!(
        io.0.lock().unwrap().as_slice(),
        std::slice::from_ref(&report.built.bytes)
    );
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
