// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn exchange_arms_and_awaits_capture_before_send_and_matches_response() {
    let registry = Arc::new(default_registry().unwrap());
    let response_packet = packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        9,
        12345,
    );
    let response_bytes = Builder::new(Arc::clone(&registry))
        .build(
            response_packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap()
        .bytes;
    let events = Arc::new(Mutex::new(Vec::new()));
    let limits = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptedExchangeIo {
        events: Arc::clone(&events),
        response: Arc::new(Mutex::new(Some(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response_bytes).unwrap(),
        ))),
        deliver_before_send: false,
        limits: Arc::clone(&limits),
        capture_statistics: CaptureStatistics::default(),
    };
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    let request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    let result = client
        .exchange(
            &PacketTemplate::new(request),
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
        )
        .unwrap();

    assert_eq!(
        *events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
    assert_eq!(
        limits.lock().unwrap().as_slice(),
        &[CaptureQueueLimits::default()]
    );
    assert_eq!(result.responses.len(), 1);
    assert_eq!(
        result.responses[0].response.frame.timestamp,
        std::time::UNIX_EPOCH
    );
    assert_eq!(result.sent_evidence.len(), 1);
    assert_eq!(result.sent_evidence[0].link_type, LinkType::RAW);
    assert_eq!(result.sent_evidence[0].bytes(), &result.sent[0].bytes);
    assert!(result.unanswered.is_empty());
    assert!(result.unsolicited.is_empty());
}

#[test]
fn frame_captured_before_request_send_cannot_satisfy_it() {
    let registry = Arc::new(default_registry().unwrap());
    let response_bytes = Builder::new(Arc::clone(&registry))
        .build(
            packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                9,
                12345,
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap()
        .bytes;
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(Some(
                Frame::new(std::time::SystemTime::now(), LinkType::IPV4, response_bytes).unwrap(),
            ))),
            deliver_before_send: true,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let result = client
        .exchange(
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
                ..ExchangeOptions::default()
            },
        )
        .unwrap();
    assert!(result.responses.is_empty());
    assert_eq!(result.unsolicited.len(), 1);
    assert_eq!(result.unanswered, [0]);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.pre_send_frame")
    );
}

#[test]
fn captured_ingress_time_controls_deadline_eligibility_and_latency() {
    let registry = Arc::new(default_registry().unwrap());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let request = Builder::new(Arc::clone(&registry))
        .build(
            packet(source, destination, 12_345, 9),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let response = Builder::new(Arc::clone(&registry))
        .build(
            packet(destination, source, 9, 12_345),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let prepared = vec![prepared_exchange_packet(request, source, destination)];
    let sent_at = vec![Instant::now()];
    let received_at = sent_at[0].checked_add(Duration::from_millis(1)).unwrap();
    let deadline = sent_at[0].checked_add(Duration::from_secs(1)).unwrap();

    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut accumulator = ExchangeAccumulator::new(1);
    accumulator.process(
        CapturedFrame::new(
            Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                response.bytes.clone(),
            )
            .unwrap(),
            received_at,
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

    assert_eq!(accumulator.responses.len(), 1);
    assert_eq!(accumulator.responses[0].latency, Duration::from_millis(1));
    assert_eq!(
        accumulator.responses[0].response.frame.timestamp,
        std::time::UNIX_EPOCH
    );

    let mut fallback = ExchangeAccumulator::new(1);
    fallback.process(
        CapturedFrame::without_ingress_time(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response.bytes).unwrap(),
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
    assert!(fallback.responses.is_empty());
    assert_eq!(fallback.unsolicited.len(), 1);
    assert!(
        fallback
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "capture.ingress_time_unavailable")
    );

    let expired_sent_at = vec![
        Instant::now()
            .checked_sub(Duration::from_millis(20))
            .unwrap(),
    ];
    let expired_received_at = expired_sent_at[0]
        .checked_add(Duration::from_millis(1))
        .unwrap();
    let expired_deadline = expired_sent_at[0]
        .checked_add(Duration::from_millis(10))
        .unwrap();
    let mut expired = ExchangeAccumulator::new(1);
    let outcome = expired.process(
        CapturedFrame::new(
            Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                prepared[0].built.bytes.clone(),
            )
            .unwrap(),
            expired_received_at,
        ),
        ExchangeProcessContext {
            registry: &registry,
            dissector: &dissector,
            prepared: &prepared,
            sent_at: &expired_sent_at,
            deadline: expired_deadline,
            options: &options,
        },
    );
    assert_eq!(outcome, ExchangeProcessOutcome::CorrelationDeadlineExpired);
    assert!(expired.responses.is_empty());
    assert_eq!(expired.unsolicited.len(), 1);
    assert!(expired.undecoded.is_empty());
    assert!(
        expired
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
    );
}

#[test]
fn exchange_retains_complete_frame_when_decode_fails() {
    let registry = Arc::new(default_registry().unwrap());
    let invalid = Frame::new(
        std::time::SystemTime::now(),
        LinkType::IPV4,
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(Some(invalid))),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let result = client
        .exchange(
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
                decode: crate::packet::decode::DecodeOptions {
                    max_packet_size: 3,
                    ..crate::packet::decode::DecodeOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap();
    assert_eq!(result.undecoded.len(), 1);
    assert_eq!(
        result.undecoded[0].bytes().as_ref(),
        [0xde, 0xad, 0xbe, 0xef]
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.decode_error")
    );
}

#[test]
fn exchange_surfaces_operation_and_cleanup_failures() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ReadinessAndShutdownFailIo(Arc::clone(&events)),
        TrafficPolicy::default(),
    );
    let error = client
        .exchange(
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
                ..ExchangeOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.classification().category, Category::Cleanup);
    assert!(matches!(
        error,
        ClientError::OperationAndCaptureShutdown {
            operation: LiveIoError::CaptureReadiness { .. },
            shutdown: LiveIoError::Capture { .. }
        }
    ));
    assert_eq!(*events.lock().unwrap(), ["arm", "ready", "shutdown"]);
}

#[test]
fn capture_guard_attempts_shutdown_during_unwind() {
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&shutdowns);
    let _ = std::panic::catch_unwind(move || {
        let _capture = CaptureGuard::new(DropObservedCapture(observed));
        panic!("simulate external codec panic");
    });
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn capture_guard_replays_shutdown_failure_without_second_provider_call() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut capture = CaptureGuard::new(ReadinessAndShutdownFailCapture(Arc::clone(&events)));
    let first = capture.shutdown().unwrap_err();
    let second = capture.shutdown().unwrap_err();
    assert_eq!(first, second);
    drop(capture);
    assert_eq!(*events.lock().unwrap(), ["shutdown"]);
}

#[test]
fn capture_guard_contains_shutdown_panic_and_never_retries() {
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut capture = CaptureGuard::new(PanicShutdownCapture(Arc::clone(&shutdowns)));
    let first = capture.shutdown().unwrap_err();
    let second = capture.shutdown().unwrap_err();
    assert_eq!(first, second);
    assert!(matches!(first, LiveIoError::Capture { .. }));
    drop(capture);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn active_exchange_requires_monotonic_capture_before_readiness_or_send() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        MissingMonotonicIo(Arc::clone(&events)),
        TrafficPolicy::default(),
    );
    let error = client
        .exchange(
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
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::MissingMonotonicCaptureTimestamp)
    ));
    assert_eq!(*events.lock().unwrap(), ["arm", "shutdown"]);
}
