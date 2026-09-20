// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts for analysis limits: validation, exact-frame reporting, and
//! reachability of every reassembly budget.

mod common;

use common::{
    CLIENT, SERVER, TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame,
};
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::analysis::{Error, Limits, Options, run};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::Tcp;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn limits_validate_each_finite_budget_before_input_is_read() {
    // Every ceiling the two reassembly engines enforce is reachable from
    // this type, so every one of them is refused at zero before a single
    // frame is read.
    type ZeroOne = fn(&mut Limits);
    let zeroed: [(&str, ZeroOne); 12] = [
        ("max_frames", |limits| limits.max_frames = 0),
        ("max_bytes", |limits| limits.max_bytes = 0),
        ("max_frame_bytes", |limits| limits.max_frame_bytes = 0),
        ("max_flows", |limits| limits.max_flows = 0),
        ("max_tcp_bytes_per_flow", |limits| {
            limits.max_tcp_bytes_per_flow = 0;
        }),
        ("max_tcp_reassembly_bytes", |limits| {
            limits.max_tcp_reassembly_bytes = 0;
        }),
        ("max_tcp_segments_per_flow", |limits| {
            limits.max_tcp_segments_per_flow = 0;
        }),
        ("max_ip_datagrams", |limits| limits.max_ip_datagrams = 0),
        ("max_ip_fragments_per_datagram", |limits| {
            limits.max_ip_fragments_per_datagram = 0;
        }),
        ("max_ip_bytes_per_datagram", |limits| {
            limits.max_ip_bytes_per_datagram = 0;
        }),
        ("max_ip_reassembly_bytes", |limits| {
            limits.max_ip_reassembly_bytes = 0;
        }),
        ("max_ip_outcomes", |limits| limits.max_ip_outcomes = 0),
    ];
    for (field, zero) in zeroed {
        let mut limits = Limits::default();
        zero(&mut limits);
        assert!(
            matches!(
                limits.validate(),
                Err(Error::InvalidLimit {
                    field: actual,
                    value: 0,
                    ..
                }) if actual == field
            ),
            "{field} must be refused at zero"
        );
    }
    for (field, zero) in [
        (
            "tcp_idle_expiry",
            Limits {
                tcp_idle_expiry: Duration::ZERO,
                ..Limits::default()
            },
        ),
        (
            "ip_idle_expiry",
            Limits {
                ip_idle_expiry: Duration::ZERO,
                ..Limits::default()
            },
        ),
    ] {
        assert!(
            matches!(
                zero.validate(),
                Err(Error::InvalidLimit { field: actual, .. }) if actual == field
            ),
            "{field} must be refused at zero"
        );
    }
    // The per-flow window doubles as the reordering window: at the serial
    // half-space a retransmission and a wrapped future segment stop being
    // distinguishable, and the engine refuses to run at all.
    assert!(matches!(
        Limits {
            max_tcp_bytes_per_flow: tcp::MAX_BYTES_PER_FLOW + 1,
            ..Limits::default()
        }
        .validate(),
        Err(Error::InvalidLimit {
            field: "max_tcp_bytes_per_flow",
            ..
        })
    ));
    assert!(
        Limits {
            max_tcp_bytes_per_flow: tcp::MAX_BYTES_PER_FLOW,
            ..Limits::default()
        }
        .validate()
        .is_ok()
    );
    assert!(matches!(
        Limits {
            max_bytes: 8,
            max_frame_bytes: 9,
            ..Limits::default()
        }
        .validate(),
        Err(Error::InvalidLimit {
            field: "max_frame_bytes",
            ..
        })
    ));
    assert!(matches!(
        Limits {
            max_duration: Duration::ZERO,
            ..Limits::default()
        }
        .validate(),
        Err(Error::InvalidLimit {
            field: "max_duration",
            ..
        })
    ));
    assert!(matches!(
        Limits {
            ip_idle_expiry: Duration::MAX,
            ..Limits::default()
        }
        .validate(),
        Err(Error::InvalidLimit {
            field: "ip_idle_expiry",
            ..
        })
    ));
    assert!(matches!(
        Limits {
            tcp_idle_expiry: Duration::MAX,
            ..Limits::default()
        }
        .validate(),
        Err(Error::InvalidLimit {
            field: "tcp_idle_expiry",
            ..
        })
    ));
}

fn assert_capture_limits(registry: &Arc<packetcraftr_core::registry::Registry>, frames: &[Frame]) {
    let mut capture = reader(frames);
    let error = run(
        &mut capture,
        Arc::clone(registry),
        &Options {
            limits: Limits {
                max_frames: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("second frame exceeds the aggregate frame budget");
    assert!(matches!(
        error,
        Error::Capture {
            number: 2,
            source: packetcraftr_core::analysis::pcap::Error::FrameLimitExceeded {
                actual: 2,
                limit: 1
            }
        }
    ));

    let frame_size = usize::try_from(frames[0].captured_length()).expect("frame length fits");
    let mut capture = reader(&frames[..1]);
    let error = run(
        &mut capture,
        Arc::clone(registry),
        &Options {
            limits: Limits {
                max_bytes: u64::try_from(frame_size - 1).expect("small fixture"),
                max_frame_bytes: frame_size - 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("captured bytes exceed the aggregate byte budget");
    assert!(matches!(
        error,
        Error::Capture {
            number: 1,
            source: packetcraftr_core::analysis::pcap::Error::StreamByteLimitExceeded { .. }
        }
    ));
}

fn assert_decode_flow_and_sink_limits(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    frames: &[Frame],
) {
    let frame_size = usize::try_from(frames[0].captured_length()).expect("frame length fits");
    let mut capture = reader(&frames[..1]);
    let error = run(
        &mut capture,
        Arc::clone(registry),
        &Options {
            limits: Limits {
                max_frame_bytes: frame_size - 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("decoder applies its own per-frame budget");
    assert!(matches!(error, Error::Decode { number: 1, .. }));

    let mut capture = reader(frames);
    let error = run(
        &mut capture,
        Arc::clone(registry),
        &Options {
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("second conversation exceeds the index table");
    assert!(matches!(
        error,
        Error::StreamLimit {
            number: 2,
            limit: 1
        }
    ));

    let mut capture = reader(&frames[..1]);
    let error = run(
        &mut capture,
        Arc::clone(registry),
        &Options::default(),
        |_| {
            Err(BoundaryError::execution_validation(
                "sink refused record",
                "test.sink",
                "fix the fixture",
            ))
        },
    )
    .expect_err("sink failure crosses the boundary");
    assert!(matches!(
        error,
        Error::Sink { number: 1, ref source } if source.to_string() == "sink refused record"
    ));
}

#[test]
fn pipeline_reports_aggregate_decode_flow_and_sink_limits_at_the_exact_frame() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 1_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            TcpSpec {
                source_port: 40_001,
                ..client_tcp(200, 0, Tcp::SYN, 1_000)
            },
            b"",
        ),
    ];

    assert_capture_limits(&registry, &frames);
    assert_decode_flow_and_sink_limits(&registry, &frames);
}

/// A handshake plus two out-of-order payload segments, so the reassembler
/// retains pending bytes rather than delivering them immediately.
fn pending_reassembly_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> Vec<Frame> {
    let epoch = SystemTime::UNIX_EPOCH;
    vec![
        tcp_frame(registry, epoch, client_tcp(100, 0, Tcp::SYN, 4_000), b""),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 4_000),
            b"",
        ),
        // Each sequence leaves a hole after the handshake, so both segments
        // are retained instead of delivered.
        tcp_frame(
            registry,
            epoch + Duration::from_secs(2),
            client_tcp(121, 501, Tcp::ACK, 4_000),
            b"first out-of-order",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(3),
            client_tcp(161, 501, Tcp::ACK, 4_000),
            b"second out-of-order",
        ),
    ]
}

fn run_with_limits(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    frames: &[Frame],
    limits: Limits,
) -> Result<Vec<tcp::Event>, Error> {
    let mut capture = reader(frames);
    let mut events = Vec::new();
    run(
        &mut capture,
        Arc::clone(registry),
        &Options {
            tcp_events: true,
            limits,
            ..Options::default()
        },
        |record| {
            events.extend(record.tcp_events.iter().cloned());
            Ok(())
        },
    )?;
    Ok(events)
}

#[test]
fn analysis_limits_reach_every_tcp_reassembly_budget() {
    let registry = registry();
    let frames = pending_reassembly_frames(&registry);

    // Each byte budget is refused by the engine naming the exact value the
    // caller set, which is only possible if that value reached it.
    let bounded: [(Limits, tcp::Error); 2] = [
        (
            Limits {
                max_tcp_bytes_per_flow: 4,
                ..Limits::default()
            },
            tcp::ResourceError::FlowByteLimit { limit: 4 }.into(),
        ),
        (
            Limits {
                max_tcp_reassembly_bytes: 8,
                ..Limits::default()
            },
            tcp::ResourceError::AggregateByteLimit { limit: 8 }.into(),
        ),
    ];
    for (limits, expected) in bounded {
        let error = run_with_limits(&registry, &frames, limits)
            .expect_err("the configured TCP budget bounds the run");
        assert!(
            matches!(&error, Error::Reassembly { source, .. } if *source == expected),
            "expected {expected}, got {error}"
        );
    }

    // The segment ceiling is recoverable rather than fatal: the flow is
    // evicted and the segment retried, so reachability shows up as an
    // eviction the default budget does not produce.
    let evictions = |limits: Limits| {
        run_with_limits(&registry, &frames, limits)
            .expect("a recoverable segment ceiling does not fail the run")
            .iter()
            .filter(|event| matches!(event, tcp::Event::Evicted { .. }))
            .count()
    };
    assert_eq!(evictions(Limits::default()), 0);
    assert_eq!(
        evictions(Limits {
            max_tcp_segments_per_flow: 1,
            ..Limits::default()
        }),
        1
    );
}

#[test]
fn tcp_idle_expiry_follows_the_configured_capture_time_interval() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 4_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(30),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 4_000),
            b"",
        ),
    ];

    let evictions = |tcp_idle_expiry: Duration| {
        let mut capture = reader(&frames);
        let mut evicted = 0_usize;
        run(
            &mut capture,
            Arc::clone(&registry),
            &Options {
                tcp_events: true,
                limits: Limits {
                    tcp_idle_expiry,
                    ..Limits::default()
                },
                ..Options::default()
            },
            |record| {
                evicted += record
                    .tcp_events
                    .iter()
                    .filter(|event| matches!(event, tcp::Event::Evicted { .. }))
                    .count();
                Ok(())
            },
        )
        .expect("bounded run succeeds");
        evicted
    };

    assert_eq!(evictions(Duration::from_secs(120)), 0);
    assert_eq!(evictions(Duration::from_secs(5)), 1);
}

#[test]
fn cancellation_stops_before_reading_input_and_is_not_a_timeout() {
    // Reader construction needs the header, so cancel after opening a real header.
    let signal = packetcraftr_core::budget::Cancellation::default();
    let registry = registry();
    let mut input = reader(&[]);
    signal.cancel();
    let result = run(
        &mut input,
        registry,
        &Options {
            cancellation: Some(signal),
            ..Options::default()
        },
        |_| panic!("cancelled collector was called"),
    );
    assert!(matches!(result, Err(Error::Cancelled(_))));
}

#[test]
fn time_bounds_select_inclusive_endpoints_without_assuming_order() {
    // The third frame regresses below the second: selection follows the
    // timestamp value, never capture order.
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(
            &registry,
            epoch + Duration::new(1, 100_000_000),
            CLIENT,
            SERVER,
            1,
            9,
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::new(1, 500_000_000),
            CLIENT,
            SERVER,
            2,
            9,
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::new(1, 900_000_000),
            CLIENT,
            SERVER,
            3,
            9,
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::new(1, 250_000_000),
            CLIENT,
            SERVER,
            4,
            9,
            b"",
        ),
    ];
    let bounds = packetcraftr_core::frame::TimeBounds::new(
        Some(epoch + Duration::new(1, 500_000_000)),
        Some(epoch + Duration::new(1, 900_000_000)),
    )
    .expect("ordered bounds");
    let mut capture = reader(&frames);
    let mut matched = Vec::new();
    let summary = run(
        &mut capture,
        registry,
        &Options {
            time_bounds: Some(bounds),
            ..Options::default()
        },
        |record| {
            matched.push(record.number);
            Ok(())
        },
    )
    .expect("bounded run succeeds");
    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_matched, 2);
    assert_eq!(matched, [2, 3]);
}

#[test]
fn time_bounds_skipped_frames_still_count_against_read_limits() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(
            &registry,
            epoch + Duration::from_secs(10),
            CLIENT,
            SERVER,
            1,
            9,
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(20),
            CLIENT,
            SERVER,
            2,
            9,
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(30),
            CLIENT,
            SERVER,
            3,
            9,
            b"",
        ),
    ];
    let bounds =
        packetcraftr_core::frame::TimeBounds::new(Some(epoch + Duration::from_secs(100)), None)
            .expect("open-ended bounds");
    let mut capture = reader(&frames);
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            time_bounds: Some(bounds),
            ..Options::default()
        },
        |_| panic!("out-of-bounds frames must not reach the sink"),
    )
    .expect("bounded run succeeds");
    assert_eq!(summary.frames_read, 3);
    assert_eq!(summary.frames_matched, 0);

    // Read budgets charge skipped frames, so the window cannot dodge the
    // aggregate input ceilings.
    let mut capture = reader(&frames);
    let result = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            time_bounds: Some(bounds),
            limits: Limits {
                max_frames: 2,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    );
    assert!(result.is_err());
}

#[test]
fn time_bounds_compose_with_the_display_filter() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            CLIENT,
            SERVER,
            1,
            9,
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(100, 0, Tcp::SYN, 4_000),
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            CLIENT,
            SERVER,
            2,
            9,
            b"",
        ),
    ];
    let filter = packetcraftr_core::filter::Filter::compile(
        "udp",
        &registry,
        packetcraftr_core::filter::Options::default(),
    )
    .expect("display filter compiles");
    let bounds =
        packetcraftr_core::frame::TimeBounds::new(Some(epoch + Duration::from_secs(2)), None)
            .expect("open-ended bounds");
    let mut capture = reader(&frames);
    let mut matched = Vec::new();
    let summary = run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            time_bounds: Some(bounds),
            ..Options::default()
        },
        |record| {
            matched.push(record.number);
            Ok(())
        },
    )
    .expect("bounded run succeeds");
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(matched, [3]);
}

#[test]
fn physical_plan_skips_unrequested_indexes_without_renumbering_requested_streams() {
    let registry = registry();
    let frames = [
        udp_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            CLIENT,
            SERVER,
            40000,
            9000,
            b"a",
        ),
        udp_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(2),
            CLIENT,
            SERVER,
            40001,
            9000,
            b"b",
        ),
    ];
    let mut options = Options {
        plan: packetcraftr_core::analysis::Plan::physical(Default::default()),
        limits: Limits {
            max_flows: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let summary = run(&mut reader(&frames), registry.clone(), &options, |record| {
        assert!(record.physical_context().udp_stream.is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.frames_read, 2);

    let filter = packetcraftr_core::filter::Filter::compile(
        "udp.stream == 0",
        &registry,
        Default::default(),
    )
    .unwrap();
    options.plan = packetcraftr_core::analysis::Plan::physical(filter.requirements());
    assert!(run(&mut reader(&frames), registry.clone(), &options, |_| Ok(())).is_err());
    options.limits.max_flows = 2;
    let mut indexes = Vec::new();
    run(&mut reader(&frames), registry, &options, |record| {
        indexes.push(record.physical_context().udp_stream);
        Ok(())
    })
    .unwrap();
    assert_eq!(indexes, [Some(0), Some(1)]);
}

#[test]
fn physical_plan_preserves_stream_numbers_after_fragmented_conversations() {
    use common::ip_fragments::ipv4_protocol_fragment_frame;
    use packetcraftr_core::analysis::Plan;
    use packetcraftr_core::filter::Filter;

    let registry = registry();
    for (protocol, query) in [(6, "tcp.stream == 1"), (17, "udp.stream == 1")] {
        let transport_frame = |port, seconds| {
            let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
            if protocol == 6 {
                tcp_frame(
                    &registry,
                    timestamp,
                    TcpSpec {
                        source_port: port,
                        ..client_tcp(1, 0, Tcp::ACK, 8192)
                    },
                    b"fragmented payload",
                )
            } else {
                udp_frame(&registry, timestamp, CLIENT, SERVER, port, 9000, b"payload")
            }
        };
        let whole = transport_frame(40000, 0);
        let payload = &whole.bytes()[20..];
        let frames = [
            ipv4_protocol_fragment_frame(
                &registry,
                SystemTime::UNIX_EPOCH,
                42,
                protocol,
                0,
                true,
                &payload[..8],
            ),
            ipv4_protocol_fragment_frame(
                &registry,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                42,
                protocol,
                1,
                false,
                &payload[8..],
            ),
            transport_frame(40001, 2),
            transport_frame(40002, 3),
        ];
        let filter = Filter::compile(query, &registry, Default::default()).unwrap();
        for plan in [Plan::default(), Plan::physical(filter.requirements())] {
            let mut indexes = Vec::new();
            let mut selected = Vec::new();
            let mut completions = 0;
            let options = Options {
                plan,
                ..Default::default()
            };
            let summary = run(&mut reader(&frames), registry.clone(), &options, |record| {
                let context = record.physical_context();
                indexes.push(if protocol == 6 {
                    context.tcp_stream
                } else {
                    context.udp_stream
                });
                if filter.matches(&context).unwrap() {
                    selected.push(record.number);
                }
                completions += record.derived_datagrams().len();
                Ok(())
            })
            .unwrap();
            assert_eq!(summary.frames_read, 4);
            assert_eq!(completions, 1);
            assert_eq!(indexes, [None, None, Some(1), Some(2)], "{query}");
            assert_eq!(selected, [3], "{query}");
        }
    }
}
