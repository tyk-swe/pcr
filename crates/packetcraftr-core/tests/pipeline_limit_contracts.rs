// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{TcpSpec, client_tcp, reader, registry, tcp_frame};
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::analysis::{Error, Limits, Options, run};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::Tcp;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn with(edit: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    edit(&mut limits);
    limits
}

#[test]
fn limits_validate_finite_budget_before_read() {
    type ZeroOne = fn(&mut Limits);
    let zeroed: [(&str, ZeroOne); 13] = [
        ("max_frames", |limits| limits.max_frames = 0),
        ("max_bytes", |limits| limits.max_bytes = 0),
        ("max_frame_bytes", |limits| limits.max_frame_bytes = 0),
        ("max_flows", |limits| limits.max_flows = 0),
        ("max_tcp_flows", |limits| limits.tcp.max_flows = 0),
        ("max_tcp_bytes_per_flow", |limits| {
            limits.tcp.max_bytes_per_flow = 0;
        }),
        ("max_tcp_reassembly_bytes", |limits| {
            limits.tcp.max_aggregate_bytes = 0;
        }),
        ("max_tcp_segments_per_flow", |limits| {
            limits.tcp.max_segments_per_flow = 0;
        }),
        ("max_ip_datagrams", |limits| limits.ip.max_datagrams = 0),
        ("max_ip_fragments_per_datagram", |limits| {
            limits.ip.max_fragments_per_datagram = 0;
        }),
        ("max_ip_bytes_per_datagram", |limits| {
            limits.ip.max_bytes_per_datagram = 0;
        }),
        ("max_ip_reassembly_bytes", |limits| {
            limits.ip.max_aggregate_bytes = 0;
        }),
        ("max_ip_outcomes", |limits| {
            limits.ip.max_retained_outcomes = 0;
        }),
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
            with(|limits| limits.tcp.idle_expiry = Duration::ZERO),
        ),
        (
            "ip_idle_expiry",
            with(|limits| limits.ip.idle_expiry = Duration::ZERO),
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
        with(|limits| limits.tcp.max_bytes_per_flow = tcp::MAX_BYTES_PER_FLOW + 1).validate(),
        Err(Error::InvalidLimit {
            field: "max_tcp_bytes_per_flow",
            ..
        })
    ));
    assert!(
        with(|limits| limits.tcp.max_bytes_per_flow = tcp::MAX_BYTES_PER_FLOW)
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
        with(|limits| limits.ip.idle_expiry = Duration::MAX).validate(),
        Err(Error::InvalidLimit {
            field: "ip_idle_expiry",
            ..
        })
    ));
    assert!(matches!(
        with(|limits| limits.tcp.idle_expiry = Duration::MAX).validate(),
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
            source: packetcraftr_core::capture_file::Error::FrameLimitExceeded {
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
            source: packetcraftr_core::capture_file::Error::StreamByteLimitExceeded { .. }
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
fn pipeline_reports_limits_at_exact_frame() {
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

#[test]
fn cancel_stops_before_input_not_timeout() {
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
