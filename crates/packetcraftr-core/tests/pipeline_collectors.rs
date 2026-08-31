// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{
    CLIENT, SERVER, TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame,
};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::expert::Finding;
use packetcraftr_core::analysis::follow::Direction as FollowDirection;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::analysis::{
    Error, IpFamilyCounters, IpReassemblyReport, Limits, Options, StreamRef, StreamTransport,
    Summary as RunSummary, run,
};
use packetcraftr_core::build::Builder;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;

fn tunnel_endpoints(spec: &TcpSpec) -> (Ipv4Addr, Ipv4Addr) {
    let client = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(203, 0, 113, 2);
    if spec.source == CLIENT {
        (client, server)
    } else {
        (server, client)
    }
}

fn tcp_header(spec: &TcpSpec) -> Tcp {
    Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options.clone(),
        ..Tcp::default()
    }
}

fn build_ipv4_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    packet: Packet,
) -> Frame {
    let built = Builder::new(Arc::clone(registry))
        .build(
            packet,
            packetcraftr_core::build::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("tunnel fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("tunnel fixture frame must be valid")
}

fn vxlan_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    vni: u32,
    spec: &TcpSpec,
) -> Frame {
    let (outer_source, outer_destination) = tunnel_endpoints(spec);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: outer_source,
        destination: outer_destination,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 50_000,
        destination_port: 4_789,
        ..Udp::default()
    });
    packet.push(Vxlan {
        vni,
        ..Vxlan::default()
    });
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(tcp_header(spec));
    build_ipv4_frame(registry, timestamp, packet)
}

fn gre_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    key: u32,
    spec: &TcpSpec,
) -> Frame {
    let (outer_source, outer_destination) = tunnel_endpoints(spec);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: outer_source,
        destination: outer_destination,
        ..Ipv4::default()
    });
    packet.push(Gre {
        key: Some(key),
        ..Gre::default()
    });
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(tcp_header(spec));
    build_ipv4_frame(registry, timestamp, packet)
}

#[test]
fn expert_public_models_and_collector_keep_their_contracts() {
    type Finish = fn(
        packetcraftr_core::analysis::expert::Collector,
        &packetcraftr_core::analysis::Summary,
    ) -> (Vec<Finding>, packetcraftr_core::analysis::expert::Summary);

    fn assert_model<T: Clone + std::fmt::Debug + Eq>() {}
    fn assert_collector<T: Default + std::fmt::Debug>() {}
    fn observe<'record>(
        collector: &mut packetcraftr_core::analysis::expert::Collector,
        record: &packetcraftr_core::analysis::FrameRecord<'record>,
    ) -> Vec<Finding> {
        collector.observe(record)
    }

    assert_model::<Finding>();
    assert_model::<packetcraftr_core::analysis::expert::Summary>();
    assert_model::<StreamRef>();
    assert_model::<StreamTransport>();
    assert_collector::<packetcraftr_core::analysis::expert::Collector>();

    let _: fn() -> packetcraftr_core::analysis::expert::Collector =
        packetcraftr_core::analysis::expert::Collector::new;
    let _: for<'record> fn(
        &mut packetcraftr_core::analysis::expert::Collector,
        &packetcraftr_core::analysis::FrameRecord<'record>,
    ) -> Vec<Finding> = observe;
    let _: Finish = packetcraftr_core::analysis::expert::Collector::finish;
}

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

#[test]
fn pipeline_assigns_stable_indices_before_filtering() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 1_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            TcpSpec {
                source_port: 40_001,
                sequence: 200,
                ..client_tcp(0, 0, Tcp::SYN, 1_000)
            },
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            TcpSpec {
                destination_port: 40_001,
                ..server_tcp(500, 201, Tcp::SYN | Tcp::ACK, 1_000)
            },
            b"",
        ),
    ];
    let filter = Filter::compile(
        "tcp.stream == 1",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("stream filter compiles");
    let mut capture = reader(&frames);
    let mut seen = Vec::new();
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |record| {
            assert!(record.tcp_events.is_empty());
            seen.push((record.number, record.tcp_stream, record.udp_stream));
            Ok(())
        },
    )
    .expect("filtered analysis succeeds");
    assert_eq!(seen, vec![(2, Some(1), None), (3, Some(1), None)]);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(summary.frames_matched, 2);
    assert!(summary.trailing_tcp_events.is_empty());
}

#[test]
fn identical_tcp_tuples_on_distinct_pcapng_interfaces_get_distinct_streams() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let mut frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 1_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(100, 0, Tcp::SYN, 1_000),
            b"",
        ),
    ];
    let mut writer = Writer::pcapng(Vec::new()).expect("PCAPNG writer initializes");
    let first_interface = writer
        .add_interface(LinkType::IPV4)
        .expect("first interface is declared");
    let second_interface = writer
        .add_interface(LinkType::IPV4)
        .expect("second interface is declared");
    frames[0].interface = Some(first_interface);
    frames[1].interface = Some(second_interface);
    for frame in &frames {
        writer.write_frame(frame).expect("PCAPNG frame writes");
    }

    let mut capture = Reader::new(Cursor::new(writer.into_inner())).expect("PCAPNG capture opens");
    let mut seen = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        seen.push((record.decoded.frame.interface, record.tcp_stream));
        Ok(())
    })
    .expect("scoped interface analysis succeeds");
    assert_eq!(
        seen,
        vec![
            (Some(first_interface), Some(0)),
            (Some(second_interface), Some(1))
        ]
    );
}

#[test]
fn vxlan_vni_scopes_inner_streams_and_preserves_reverse_direction_identity() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let client = client_tcp(100, 0, Tcp::SYN, 1_000);
    let server = server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 1_000);
    let frames = [
        vxlan_tcp_frame(&registry, epoch, 10, &client),
        vxlan_tcp_frame(&registry, epoch + Duration::from_secs(1), 10, &server),
        vxlan_tcp_frame(&registry, epoch + Duration::from_secs(2), 20, &client),
    ];
    let mut capture = reader(&frames);
    let mut streams = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        streams.push(record.tcp_stream);
        Ok(())
    })
    .expect("VXLAN analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(0), Some(1)]);
}

#[test]
fn gre_keys_scope_identical_inner_tcp_tuples() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let flow = client_tcp(100, 0, Tcp::SYN, 1_000);
    let frames = [
        gre_tcp_frame(&registry, epoch, 1, &flow),
        gre_tcp_frame(&registry, epoch + Duration::from_secs(1), 2, &flow),
    ];
    let mut capture = reader(&frames);
    let mut streams = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        streams.push(record.tcp_stream);
        Ok(())
    })
    .expect("GRE analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(1)]);
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

#[test]
fn stats_collect_all_tables_with_directional_and_time_accounting() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(100, 0, Tcp::SYN, 2_000),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 2_000),
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(4),
            CLIENT,
            SERVER,
            9_999,
            9_999,
            b"datagram",
        ),
    ];
    let total_bytes = frames
        .iter()
        .map(|frame| u64::from(frame.captured_length()))
        .sum::<u64>();
    let tcp_bytes = u64::from(frames[0].captured_length()) + u64::from(frames[1].captured_length());
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::stats::Collector::new(Duration::from_secs(1))
        .expect("valid interval");
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options::default(),
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .expect("statistics pass succeeds");
    let report = collector.finish(&summary);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(report.frames, 3);
    assert_eq!(report.bytes, total_bytes);
    assert_eq!(report.first_timestamp, Some(epoch + Duration::from_secs(1)));
    assert_eq!(report.last_timestamp, Some(epoch + Duration::from_secs(4)));
    assert_eq!(report.io.len(), 2);
    assert_eq!(report.io[0].offset, Duration::ZERO);
    assert_eq!(report.io[0].frames, 2);
    assert_eq!(report.io[1].offset, Duration::from_secs(2));
    assert_eq!(report.io[1].frames, 1);

    let ipv4 = report
        .protocols
        .iter()
        .find(|row| row.protocol == "ipv4")
        .expect("IPv4 protocol row");
    assert_eq!((ipv4.frames, ipv4.bytes), (3, total_bytes));
    assert_eq!(report.protocols[0].frames, 3);
    assert_eq!(report.conversations.len(), 2);
    let tcp = report
        .conversations
        .iter()
        .find(|row| row.transport == StreamTransport::Tcp)
        .expect("TCP conversation row");
    assert_eq!(tcp.stream, 0);
    assert_eq!(tcp.frames_a_to_b, 1);
    assert_eq!(tcp.frames_b_to_a, 1);
    assert_eq!(tcp.bytes_a_to_b + tcp.bytes_b_to_a, tcp_bytes);
    assert_eq!(tcp.duration(), Duration::from_secs(1));
    let udp = report
        .conversations
        .iter()
        .find(|row| row.transport == StreamTransport::Udp)
        .expect("UDP conversation row");
    assert_eq!(udp.stream, 0);
    assert_eq!(udp.frames_a_to_b, 1);
    assert_eq!(StreamTransport::Udp.as_str(), "udp");

    assert_eq!(report.endpoints.len(), 2);
    let client = report
        .endpoints
        .iter()
        .find(|row| row.address == IpAddr::V4(CLIENT))
        .expect("client endpoint");
    assert_eq!(client.tx_frames, 2);
    assert_eq!(client.rx_frames, 1);
    let udp_port = report
        .ports
        .iter()
        .find(|row| row.transport == StreamTransport::Udp && row.port == 9_999)
        .expect("UDP port row");
    assert_eq!(
        udp_port.frames, 1,
        "same source/destination port counts once"
    );
}

#[test]
fn stats_reject_zero_interval_and_empty_report_is_well_formed() {
    assert!(matches!(
        packetcraftr_core::analysis::stats::Collector::new(Duration::ZERO),
        Err(Error::InvalidLimit {
            field: "interval",
            value: 0,
            ..
        })
    ));
    let report = packetcraftr_core::analysis::stats::Collector::new(Duration::from_millis(250))
        .expect("valid interval")
        .finish(&RunSummary::default());
    assert_eq!(report.frames, 0);
    assert_eq!(report.bytes, 0);
    assert!(report.first_timestamp.is_none());
    assert!(report.protocols.is_empty());
    assert!(report.conversations.is_empty());
    assert!(report.io.is_empty());
    assert_eq!(report.ip_reassembly, IpReassemblyReport::default());

    let ip_reassembly = IpReassemblyReport {
        counters: packetcraftr_core::analysis::IpCounters {
            ipv4: IpFamilyCounters {
                physical_fragments: 2,
                completed_datagrams: 1,
                derived_datagram_bytes: 44,
                derived_payload_bytes: 24,
                ..IpFamilyCounters::default()
            },
            ..packetcraftr_core::analysis::IpCounters::default()
        },
        outcomes_omitted: 3,
        ..IpReassemblyReport::default()
    };
    let report = packetcraftr_core::analysis::stats::Collector::new(Duration::from_millis(250))
        .expect("valid interval")
        .finish(&RunSummary {
            ip_reassembly: ip_reassembly.clone(),
            ..RunSummary::default()
        });
    assert_eq!(report.ip_reassembly, ip_reassembly);
    assert_eq!(report.frames, 0);
    assert_eq!(report.bytes, 0);
}

#[test]
fn tcp_follow_delivers_gap_fill_in_order_and_classifies_both_directions() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 2_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(104, 0, Tcp::ACK, 2_000),
            b"def",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 0, Tcp::ACK, 2_000),
            b"abc",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            server_tcp(500, 107, Tcp::ACK, 2_000),
            b"xy",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("follow pass succeeds");
    let summary = collector.finish(&run_summary);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].number, 3);
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[0].bytes.as_ref(), b"abcdef");
    assert_eq!(chunks[1].direction, FollowDirection::ServerToClient);
    assert_eq!(chunks[1].bytes.as_ref(), b"xy");
    assert_eq!(summary.frames, 4);
    assert_eq!(summary.client_bytes, 6);
    assert_eq!(summary.server_bytes, 2);
    assert_eq!(summary.undelivered_bytes, 0);
    assert_eq!(
        summary
            .client_flow
            .as_ref()
            .expect("client established")
            .source,
        IpAddr::V4(CLIENT)
    );
}

#[test]
fn tcp_follow_deduplicates_fast_open_data_across_directional_close() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 8_192), b"A"),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 501, Tcp::ACK, 8_192),
            b"A",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            client_tcp(102, 501, Tcp::FIN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(4),
            client_tcp(101, 501, Tcp::ACK, 8_192),
            b"A",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("Fast Open follow pass succeeds");
    let summary = collector.finish(&run_summary);

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[0].bytes.as_ref(), b"A");
    assert_eq!(summary.client_bytes, 1);
    assert_eq!(summary.server_bytes, 0);
}

#[test]
fn tcp_follow_starts_a_fresh_delivery_generation_for_four_tuple_reuse() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 8_192), b"A"),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 102, Tcp::SYN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(102, 501, Tcp::FIN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            client_tcp(100, 0, Tcp::SYN, 8_192),
            b"B",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("reused four-tuple follow pass succeeds");
    let summary = collector.finish(&run_summary);

    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.bytes.as_ref())
            .collect::<Vec<_>>(),
        [b"A".as_slice(), b"B".as_slice()]
    );
    assert_eq!(summary.client_bytes, 2);
    assert_eq!(summary.server_bytes, 0);
}

#[test]
fn udp_follow_emits_empty_and_nonempty_datagrams_and_ignores_other_streams() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(&registry, epoch, CLIENT, SERVER, 4_000, 9_000, b"query"),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            SERVER,
            CLIENT,
            9_000,
            4_000,
            b"answer",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            CLIENT,
            SERVER,
            4_001,
            9_000,
            b"other",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options::default(),
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("UDP follow succeeds");
    let summary = collector.finish(&run_summary);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].bytes.as_ref(), b"query");
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[1].bytes.as_ref(), b"answer");
    assert_eq!(chunks[1].direction, FollowDirection::ServerToClient);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 5);
    assert_eq!(summary.server_bytes, 6);

    let empty = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 99,
    })
    .finish(&RunSummary::default());
    assert_eq!(empty.frames, 0);
    assert!(empty.client_flow.is_none());
}

#[test]
fn tcp_follow_reports_bytes_stranded_behind_a_gap_at_end() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 2_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(105, 0, Tcp::ACK, 2_000),
            b"late",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            assert!(collector.observe(&record).is_empty());
            Ok(())
        },
    )
    .expect("follow pass succeeds");
    assert!(
        run_summary
            .trailing_tcp_events
            .iter()
            .any(|event| matches!(event, tcp::Event::Gap { .. }))
    );
    let summary = collector.finish(&run_summary);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 0);
    assert_eq!(summary.undelivered_bytes, 4);
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
