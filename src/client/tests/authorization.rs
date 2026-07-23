// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
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
    request.push(crate::packet::layer::Raw::new(vec![0_u8; 2_000]));
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
                    mode: crate::packet::build::BuildMode::Permissive,
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
    base.push(crate::packet::layer::Raw::default());
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
