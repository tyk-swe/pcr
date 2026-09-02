// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for analysis limits: validation, exact-frame reporting, and
//! reachability of every reassembly budget.

mod common;

use common::{TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame};
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
