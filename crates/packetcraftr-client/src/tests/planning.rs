// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
#[test]
fn exchange_reuses_route_lookup_for_transport_only_template_variants() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        1,
    ))
    .axis(
        1,
        "destination_port",
        TemplateValues::UnsignedRange {
            start: 1,
            end_inclusive: 64,
        },
    );
    let options = ExchangeOptions {
        send: SendOptions {
            plan: PlanOptions {
                link_mode: LinkMode::Layer3,
                ..PlanOptions::default()
            },
            ..SendOptions::default()
        },
        ..ExchangeOptions::default()
    };

    let result = client.exchange(&template, options.clone()).unwrap();
    assert_eq!(result.sent.len(), 64);
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);

    client.exchange(&template, options).unwrap();
    assert_eq!(route_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn exchange_uses_one_route_lookup_per_distinct_lookup_destination() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ))
    .axis(
        0,
        "destination",
        TemplateValues::Values(vec![
            FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
            FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 3)),
        ]),
    );

    let result = client
        .exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap();
    assert_eq!(result.sent.len(), 2);
    assert_eq!(route_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn heterogeneous_exchange_routes_fail_before_capture_or_transmission() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        DestinationRoutes {
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ))
    .axis(
        0,
        "destination",
        TemplateValues::Values(vec![
            FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
            FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 3)),
        ]),
    );

    assert!(matches!(
        client.exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        ),
        Err(ClientError::HeterogeneousExchangeRoute)
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 2);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn exchange_policy_checks_are_not_bypassed_by_cached_route_decisions() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ))
    .axis(
        0,
        "options",
        TemplateValues::Values(vec![
            FieldValue::Bytes(Bytes::new()),
            FieldValue::Bytes(Bytes::from_static(&[131, 7, 4, 8, 8, 8, 8])),
        ]),
    );

    assert!(matches!(
        client.exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        ),
        Err(ClientError::Policy(TrafficPolicyError::PublicDestination { destination }))
            if destination == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn expired_preparation_does_not_start_a_second_route_lookup() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        SlowRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
            delay: Duration::from_millis(300),
        },
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ))
    .axis(
        1,
        "destination_port",
        TemplateValues::UnsignedRange {
            start: 9,
            end_inclusive: 10,
        },
    );
    let error = client
        .exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                timeout: Duration::from_millis(100),
                ..ExchangeOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange"
        })
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn capture_loss_is_a_typed_failure_or_visible_diagnostic_by_policy() {
    let statistics = CaptureStatistics {
        received_frames: 3,
        received_bytes: 192,
        dropped_frames: 2,
        dropped_bytes: 128,
        overflow_events: 1,
        receiver_dropped_frames: 0,
    };

    let error =
        exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::Fail).unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::CaptureQueueOverflow {
            dropped_frames: 2,
            dropped_bytes: 128,
            overflow_events: 1,
        })
    ));

    for policy in [
        CaptureOverflowPolicy::DropNewest,
        CaptureOverflowPolicy::DropOldest,
    ] {
        let result = exchange_with_capture_statistics(statistics, policy).unwrap();
        assert_eq!(result.stats.capture, statistics, "{policy:?}");
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "capture.evidence_incomplete")
        );
    }
}

#[test]
fn receiver_loss_is_not_reported_as_queue_overflow() {
    let statistics = CaptureStatistics {
        dropped_frames: 3,
        receiver_dropped_frames: 3,
        ..CaptureStatistics::default()
    };

    let error =
        exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::Fail).unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::CaptureEvidenceLoss {
            dropped_frames: 3,
            receiver_dropped_frames: 3,
            ..
        })
    ));
}

#[test]
fn invalid_capture_statistics_fail_closed() {
    let statistics = CaptureStatistics {
        dropped_bytes: 1,
        ..CaptureStatistics::default()
    };
    let error = exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::DropNewest)
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::InvalidCaptureStatistics { .. })
    ));
}

#[test]
fn raw_layer3_backend_never_receives_canonical_link_layer_bytes() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy::default(),
    );

    for (case, request) in canonical_link_intent_packets() {
        let error = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();

        assert!(
            matches!(error, ClientError::Plan(PlanError::EthernetInLayer3)),
            "{case}: {error}"
        );
        assert!(io.0.lock().unwrap().is_empty(), "{case}");
    }
}

#[test]
fn neighbor_failure_cannot_fall_back_from_explicit_layer2() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        FailingNeighbors,
        io.clone(),
        TrafficPolicy::default(),
    );
    let request = canonical_link_intent_packets()
        .into_iter()
        .find_map(|(case, packet)| (case == "vlan8021ad").then_some(packet))
        .unwrap();

    let error = client
        .send(
            request,
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
        ClientError::Neighbor(NeighborError::Resolution { .. })
    ));
    assert!(io.0.lock().unwrap().is_empty());
}

#[test]
fn dry_plan_keeps_spoofed_packet_and_neighbor_sources_distinct() {
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );
    let spoofed = Ipv4Addr::new(10, 9, 9, 9);
    let plan = client
        .plan(
            &packet(spoofed, Ipv4Addr::new(10, 0, 1, 5), 1000, 9),
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
        )
        .unwrap();

    assert_eq!(plan.packet_source, Some(IpAddr::V4(spoofed)));
    assert_eq!(
        plan.neighbor_source,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        plan.neighbor_target,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)))
    );
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
}

#[test]
fn send_complete_custom_ethernet_without_ip_destination() {
    let decision = RouteDecision {
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        capability: LinkCapability::Layer2,
        link_type: LinkType::ETHERNET,
        ..route(LinkCapability::Layer2)
    };
    let interface = decision.interface.clone();
    let ip_lookups = Arc::new(AtomicUsize::new(0));
    let interface_lookups = Arc::new(AtomicUsize::new(0));
    let routes = InterfaceRoutes {
        decision,
        ip_lookups: Arc::clone(&ip_lookups),
        interface_lookups: Arc::clone(&interface_lookups),
    };
    let neighbors = CountingNeighbors::default();
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        routes,
        neighbors.clone(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [2, 0, 0, 0, 0, 2],
            source: [2, 0, 0, 0, 0, 1],
            ether_type: WireValue::Exact(0x88b5),
        })
        .push(Raw::new(Bytes::from_static(b"custom")));

    let report = client
        .send(
            packet,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Auto,
                    interface: Some(interface),
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(interface_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert_eq!(report.route.plan.lookup_destination, None);
    assert_eq!(report.route.plan.final_destination, None);
    assert_eq!(
        report.built.bytes.as_ref(),
        &[
            2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x88, 0xb5, b'c', b'u', b's', b't', b'o', b'm',
        ]
    );
    assert_eq!(io.0.lock().unwrap().as_slice(), &[report.built.bytes]);
}
