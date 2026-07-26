// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
#[test]
fn exchange_deadline_boundary_and_equal_confidence_ties_are_deterministic() {
    let registry = Arc::new(default_registry().unwrap());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let builder = Builder::new(Arc::clone(&registry));
    let request = builder
        .build(
            packet(source, destination, 12_345, 9),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let response = builder
        .build(
            packet(destination, source, 9, 12_345),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let prepared = vec![
        prepared_exchange_packet(request.clone(), source, destination),
        prepared_exchange_packet(request, source, destination),
    ];
    let now = Instant::now();
    let sent_at = vec![now, now];
    let deadline = now.checked_add(Duration::from_millis(10)).unwrap();
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();

    let mut exact_boundary = ExchangeAccumulator::new(2);
    exact_boundary.process(
        CapturedFrame::new(
            Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                response.bytes.clone(),
            )
            .unwrap(),
            deadline,
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
    assert_eq!(exact_boundary.responses[0].request_index, 0);
    assert_eq!(
        exact_boundary.responses[0].latency,
        Duration::from_millis(10)
    );

    let mut after_deadline = ExchangeAccumulator::new(2);
    after_deadline.process(
        CapturedFrame::new(
            Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                response.bytes.clone(),
            )
            .unwrap(),
            deadline.checked_add(Duration::from_nanos(1)).unwrap(),
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
    assert!(after_deadline.responses.is_empty());
    assert_eq!(after_deadline.unsolicited.len(), 1);

    let mut balanced = ExchangeAccumulator::new(2);
    balanced.response_counts[0] = 1;
    balanced.process(
        CapturedFrame::new(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response.bytes).unwrap(),
            deadline,
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
    assert_eq!(balanced.responses[0].request_index, 1);
}

#[test]
fn quoted_icmp_error_uses_monotonic_ingress_latency() {
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
    let mut quote = vec![0_u8; 4];
    quote.extend_from_slice(&request.bytes[..28]);
    let mut error = Packet::new();
    error
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 254),
            destination: source,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 11,
            body: Bytes::from(quote),
            ..Icmpv4::default()
        });
    let error = Builder::new(Arc::clone(&registry))
        .build(error, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let prepared = vec![prepared_exchange_packet(request, source, destination)];
    let sent_at = vec![Instant::now()];
    let received_at = sent_at[0].checked_add(Duration::from_millis(1)).unwrap();
    let deadline = sent_at[0].checked_add(Duration::from_millis(10)).unwrap();
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut accumulator = ExchangeAccumulator::new(1);

    accumulator.process(
        CapturedFrame::new(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, error.bytes).unwrap(),
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
    assert!(accumulator.unsolicited.is_empty());
}

#[test]
fn endless_zero_time_capture_drain_is_bounded_and_send_progresses() {
    let sends = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        EndlessCaptureIo {
            frame: Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            )
            .unwrap(),
            sends: Arc::clone(&sends),
        },
        TrafficPolicy::default(),
    );
    let started = Instant::now();
    let result = client
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
                timeout: Duration::from_millis(50),
                max_capture_queue_frames: 1,
                max_unsolicited: 1,
                max_responses: 1,
                ..ExchangeOptions::default()
            },
        )
        .unwrap();

    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.drain_limit")
    );
}

#[test]
fn slow_send_consumes_absolute_deadline_and_stops_later_requests() {
    let sends = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        SlowSendIo {
            delay: Duration::from_millis(150),
            sends: Arc::clone(&sends),
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
        "source_port",
        TemplateValues::UnsignedRange {
            start: 12_345,
            end_inclusive: 12_346,
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

    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::DeadlineExceeded {
            operation: "sending exchange requests"
        })
    ));
}
