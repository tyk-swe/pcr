// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn matcher_result_is_not_committed_after_correlation_deadline_expires() {
    let mut registry_builder = RegistryBuilder::new();
    registry_builder.module(&BuiltinProtocols).unwrap();
    registry_builder.register_codec(MacSensitiveCodec).unwrap();
    registry_builder
        .bind("ethernet", 0x88b5, "test.mac_sensitive", 200)
        .unwrap();
    registry_builder
        .register_matcher("test.mac_sensitive", SlowMatcher(Duration::from_millis(75)))
        .unwrap();
    let registry = Arc::new(registry_builder.build().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            ether_type: WireValue::Exact(0x88b5),
            ..Ethernet::default()
        })
        .push(MacSensitiveLayer);
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let prepared = vec![PreparedExchangePacket {
        built: built.clone(),
        route: MaterializedRoute {
            plan: PlannedRoute {
                route: route(LinkCapability::Layer2),
                mode: LinkMode::Layer2,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        },
    }];
    let sent_at = vec![Instant::now()];
    let deadline = sent_at[0].checked_add(Duration::from_millis(50)).unwrap();
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut accumulator = ExchangeAccumulator::new(1);

    let outcome = accumulator.process(
        CapturedFrame::new(
            Frame::new(std::time::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap(),
            sent_at[0],
        ),
        ExchangeProcessContext {
            registry: &registry,
            dissector: &dissector,
            prepared: &prepared,
            sent_at: &sent_at,
            deadline,
            options: &options,
        },
    );

    assert_eq!(outcome, ExchangeProcessOutcome::CorrelationDeadlineExpired);
    assert!(accumulator.responses.is_empty());
    assert_eq!(accumulator.unsolicited.len(), 1);
    assert!(
        accumulator
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
    );
}

fn workflow_accumulator_with_unsolicited(
    promotion_deadline: impl FnOnce() -> Instant,
) -> (
    ExchangeAccumulator,
    Vec<PreparedExchangePacket>,
    Vec<Instant>,
    Instant,
) {
    let registry = Arc::new(default_registry().unwrap());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let built = Builder::new(Arc::clone(&registry))
        .build(
            packet(source, destination, 12_345, 9),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let prepared = vec![PreparedExchangePacket {
        built: built.clone(),
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
    }];
    let sent_at = vec![Instant::now()];
    let process_deadline = sent_at[0].checked_add(Duration::from_secs(1)).unwrap();
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut accumulator = ExchangeAccumulator::new(1);

    let outcome = accumulator.process(
        CapturedFrame::new(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, built.bytes.clone()).unwrap(),
            sent_at[0],
        ),
        ExchangeProcessContext {
            registry: &registry,
            dissector: &dissector,
            prepared: &prepared,
            sent_at: &sent_at,
            deadline: process_deadline,
            options: &options,
        },
    );
    assert_eq!(outcome, ExchangeProcessOutcome::Continue);
    assert!(accumulator.responses.is_empty());
    assert_eq!(accumulator.unsolicited.len(), 1);

    (accumulator, prepared, sent_at, promotion_deadline())
}

#[test]
fn expired_workflow_promotion_does_not_invoke_matcher() {
    let (mut accumulator, prepared, sent_at, deadline) =
        workflow_accumulator_with_unsolicited(|| {
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap()
        });
    let mut matcher_calls = 0;

    let outcome = accumulator.promote_workflow_unsolicited(
        WorkflowPromotionContext {
            prepared: &prepared,
            sent_at: &sent_at,
            deadline,
            max_responses: 1,
        },
        &mut |_, _, _| {
            matcher_calls += 1;
            true
        },
    );

    assert_eq!(outcome, ExchangeProcessOutcome::CorrelationDeadlineExpired);
    assert_eq!(matcher_calls, 0);
    assert!(accumulator.responses.is_empty());
    assert!(accumulator.unsolicited.is_empty());
    assert_eq!(
        accumulator
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
            .count(),
        1
    );
}

#[test]
fn workflow_promotion_crossing_deadline_is_not_committed() {
    let (mut accumulator, prepared, sent_at, deadline) =
        workflow_accumulator_with_unsolicited(|| {
            Instant::now()
                .checked_add(Duration::from_millis(100))
                .unwrap()
        });
    let mut matcher_calls = 0;

    let outcome = accumulator.promote_workflow_unsolicited(
        WorkflowPromotionContext {
            prepared: &prepared,
            sent_at: &sent_at,
            deadline,
            max_responses: 1,
        },
        &mut |_, _, _| {
            matcher_calls += 1;
            std::thread::sleep(Duration::from_millis(150));
            true
        },
    );

    assert_eq!(outcome, ExchangeProcessOutcome::CorrelationDeadlineExpired);
    assert_eq!(matcher_calls, 1);
    assert!(accumulator.responses.is_empty());
    assert!(accumulator.unsolicited.is_empty());
    assert!(
        accumulator
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
    );
}

#[test]
fn workflow_promotion_runs_before_native_capture_wait_consumes_deadline() {
    let registry = Arc::new(default_registry().unwrap());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let request = packet(source, destination, 12_345, 9);
    let response = Builder::new(Arc::clone(&registry))
        .build(
            request.clone(),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        DeadlineConsumingExchangeIo {
            events: Arc::clone(&events),
            response: Arc::new(Mutex::new(Some(
                Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response.bytes).unwrap(),
            ))),
        },
        TrafficPolicy::default(),
    );

    let result = client
        .exchange_for_workflow(
            &PacketTemplate::new(request),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                timeout: Duration::from_millis(50),
                max_responses: 1,
                ..ExchangeOptions::default()
            },
            |_, _, _| {
                events.lock().unwrap().push("promote");
                true
            },
        )
        .unwrap();

    let events = events.lock().unwrap();
    let promotion = events.iter().position(|event| *event == "promote").unwrap();
    let native_wait = events
        .iter()
        .position(|event| *event == "capture_wait")
        .unwrap();
    assert!(promotion < native_wait, "events: {events:?}");
    assert_eq!(result.responses.len(), 1);
    assert!(result.unanswered.is_empty());
    assert!(result.unsolicited.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "exchange.correlation_deadline")
    );
}

#[test]
fn built_in_workflow_path_cannot_promote_a_frame_without_ingress_time() {
    let registry = Arc::new(default_registry().unwrap());
    let response = Builder::new(Arc::clone(&registry))
        .build(
            packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                9,
                12_345,
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let io = UnmarkedExchangeIo(ScriptedExchangeIo {
        events: Arc::new(Mutex::new(Vec::new())),
        response: Arc::new(Mutex::new(Some(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response.bytes).unwrap(),
        ))),
        deliver_before_send: false,
        limits: Arc::new(Mutex::new(Vec::new())),
        capture_statistics: CaptureStatistics::default(),
    });
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    let mut matcher_calls = 0;
    let result = client
        .exchange_for_workflow(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12_345,
                9,
            )),
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
            |_, _, _| {
                matcher_calls += 1;
                true
            },
        )
        .unwrap();
    assert_eq!(matcher_calls, 0);
    assert!(result.responses.is_empty());
    assert!(result.unsolicited.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "capture.ingress_time_unavailable")
    );
}
