// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_analysis::expert::{
    ExpertCollector, ExpertSummary, Finding, StreamRef, StreamTransport,
};
use packetcraftr_analysis::follow::{Direction as FollowDirection, FollowCollector, Selector};
use packetcraftr_analysis::pcap::{Reader, Writer};
use packetcraftr_analysis::reassembly::tcp;
use packetcraftr_analysis::stats::{StatsCollector, TransportKind};
use packetcraftr_analysis::{Error, Limits, Options, run};
use packetcraftr_packet::Packet;
use packetcraftr_packet::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_packet::error::{BoundaryError, Classified, Kind};
use packetcraftr_packet::filter::{Filter, Options as FilterOptions};
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::layer::Raw;
use packetcraftr_packet::protocol::builtin;
use packetcraftr_packet::protocol::network::Ipv4;
use packetcraftr_packet::protocol::transport::{Tcp, Udp};
use packetcraftr_packet::registry::Registry;

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

#[test]
fn expert_public_models_and_collector_keep_their_contracts() {
    type Finish = fn(ExpertCollector, &[tcp::Event], u64) -> (Vec<Finding>, ExpertSummary);

    fn assert_model<T: Clone + std::fmt::Debug + Eq>() {}
    fn assert_collector<T: Default + std::fmt::Debug>() {}
    fn observe<'record>(
        collector: &mut ExpertCollector,
        record: &packetcraftr_analysis::FrameRecord<'record>,
    ) -> Vec<Finding> {
        collector.observe(record)
    }

    assert_model::<Finding>();
    assert_model::<ExpertSummary>();
    assert_model::<StreamRef>();
    assert_model::<StreamTransport>();
    assert_collector::<ExpertCollector>();

    let _: fn() -> ExpertCollector = ExpertCollector::new;
    let _: for<'record> fn(
        &mut ExpertCollector,
        &packetcraftr_analysis::FrameRecord<'record>,
    ) -> Vec<Finding> = observe;
    let _: Finish = ExpertCollector::finish;
}

fn registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in protocols must register"))
}

#[derive(Clone, Copy)]
struct TcpSpec {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    window: u16,
}

fn tcp_frame(
    registry: &Arc<Registry>,
    timestamp: SystemTime,
    spec: TcpSpec,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("TCP fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("TCP fixture frame must be valid")
}

fn udp_frame(
    registry: &Arc<Registry>,
    timestamp: SystemTime,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port,
        destination_port,
        ..Udp::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    let built = Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("UDP fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("UDP fixture frame must be valid")
}

fn reader(frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).expect("capture writer initializes");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fixture capture opens")
}

fn client_tcp(sequence: u32, acknowledgment: u32, flags: u16, window: u16) -> TcpSpec {
    TcpSpec {
        source: CLIENT,
        destination: SERVER,
        source_port: 40_000,
        destination_port: 443,
        sequence,
        acknowledgment,
        flags,
        window,
    }
}

fn server_tcp(sequence: u32, acknowledgment: u32, flags: u16, window: u16) -> TcpSpec {
    TcpSpec {
        source: SERVER,
        destination: CLIENT,
        source_port: 443,
        destination_port: 40_000,
        sequence,
        acknowledgment,
        flags,
        window,
    }
}

#[test]
fn limits_validate_each_finite_budget_before_input_is_read() {
    for field in [
        "max_frames",
        "max_bytes",
        "max_frame_bytes",
        "max_indexed_flows",
        "max_flows",
    ] {
        let mut limits = Limits::default();
        match field {
            "max_frames" => limits.max_frames = 0,
            "max_bytes" => limits.max_bytes = 0,
            "max_frame_bytes" => limits.max_frame_bytes = 0,
            "max_indexed_flows" => limits.max_indexed_flows = 0,
            "max_flows" => limits.max_flows = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidLimit {
                field: actual,
                value: 0,
                ..
            }) if actual == field
        ));
    }
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
                source_port: 443,
                source: SERVER,
                destination: CLIENT,
                sequence: 500,
                acknowledgment: 201,
                flags: Tcp::SYN | Tcp::ACK,
                window: 1_000,
            },
            b"",
        ),
    ];
    let filter = Filter::compile(
        "tcp.stream == 1",
        registry.as_ref(),
        FilterOptions::default(),
    )
    .expect("stream filter compiles");
    let mut capture = reader(&frames);
    let mut seen = Vec::new();
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            filter: Some(&filter),
            limits: Limits {
                max_indexed_flows: 2,
                max_flows: 1,
                ..Limits::default()
            },
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
fn rejected_flows_only_charge_indexing_when_stream_fields_require_it() {
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
    let packet_filter = Filter::compile(
        "tcp.source_port == 40001",
        registry.as_ref(),
        FilterOptions::default(),
    )
    .expect("packet-field filter compiles");
    assert!(!packet_filter.requirements().stream_index);
    let mut capture = reader(&frames);
    let mut seen = Vec::new();
    run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            filter: Some(&packet_filter),
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            seen.push((record.number, record.tcp_stream));
            Ok(())
        },
    )
    .expect("rejected flow does not consume selected-flow budget");
    assert_eq!(seen, vec![(2, Some(0))]);

    let tcp_only_filter = Filter::compile(
        "tcp.stream == 0",
        registry.as_ref(),
        FilterOptions::default(),
    )
    .expect("TCP stream-field filter compiles");
    assert!(tcp_only_filter.requirements().tcp_stream);
    assert!(!tcp_only_filter.requirements().udp_stream);
    let mixed_frames = [
        udp_frame(
            &registry,
            epoch,
            CLIENT,
            SERVER,
            50_000,
            9_999,
            b"first rejected UDP flow",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            CLIENT,
            SERVER,
            50_001,
            9_999,
            b"second rejected UDP flow",
        ),
        frames[0].clone(),
    ];
    let mut capture = reader(&mixed_frames);
    let mut seen = Vec::new();
    run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            filter: Some(&tcp_only_filter),
            limits: Limits {
                max_indexed_flows: 1,
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            seen.push((record.number, record.tcp_stream));
            Ok(())
        },
    )
    .expect("an unrequested UDP index does not consume the TCP indexing budget");
    assert_eq!(seen, vec![(3, Some(0))]);

    let stream_filter = Filter::compile(
        "tcp.stream == 1",
        registry.as_ref(),
        FilterOptions::default(),
    )
    .expect("stream-field filter compiles");
    let mut capture = reader(&frames);
    let error = run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&stream_filter),
            limits: Limits {
                max_indexed_flows: 1,
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("stream-field filter requires bounded prefilter indexing");
    assert!(matches!(
        error,
        Error::StreamIndexLimit {
            number: 2,
            limit: 1
        }
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

    let mut capture = reader(&frames);
    let error = run(
        &mut capture,
        Arc::clone(&registry),
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
            source: packetcraftr_analysis::pcap::Error::FrameLimitExceeded {
                actual: 2,
                limit: 1
            }
        }
    ));

    let frame_size = usize::try_from(frames[0].captured_length()).expect("frame length fits");
    let mut capture = reader(&frames[..1]);
    let error = run(
        &mut capture,
        Arc::clone(&registry),
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
            source: packetcraftr_analysis::pcap::Error::StreamByteLimitExceeded { .. }
        }
    ));

    let mut capture = reader(&frames[..1]);
    let error = run(
        &mut capture,
        Arc::clone(&registry),
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

    let mut capture = reader(&frames);
    let error = run(
        &mut capture,
        Arc::clone(&registry),
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
    let error = run(&mut capture, registry, &Options::default(), |_| {
        Err(BoundaryError::execution_validation(
            "sink refused record",
            "test.sink",
            "fix the fixture",
        ))
    })
    .expect_err("sink failure crosses the boundary");
    assert!(matches!(
        error,
        Error::Sink { number: 1, ref source } if source.to_string() == "sink refused record"
    ));
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
    let mut collector = StatsCollector::new(Duration::from_secs(1)).expect("valid interval");
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options::default(),
        |record| {
            collector.observe(&record).expect("record has capture time");
            Ok(())
        },
    )
    .expect("statistics pass succeeds");
    let report = collector.finish();
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
        .find(|row| row.transport == TransportKind::Tcp)
        .expect("TCP conversation row");
    assert_eq!(tcp.stream, 0);
    assert_eq!(tcp.frames_a_to_b, 1);
    assert_eq!(tcp.frames_b_to_a, 1);
    assert_eq!(tcp.bytes_a_to_b + tcp.bytes_b_to_a, tcp_bytes);
    assert_eq!(tcp.duration(), Duration::from_secs(1));
    let udp = report
        .conversations
        .iter()
        .find(|row| row.transport == TransportKind::Udp)
        .expect("UDP conversation row");
    assert_eq!(udp.stream, 0);
    assert_eq!(udp.frames_a_to_b, 1);
    assert_eq!(TransportKind::Udp.as_str(), "udp");

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
        .find(|row| row.transport == TransportKind::Udp && row.port == 9_999)
        .expect("UDP port row");
    assert_eq!(
        udp_port.frames, 1,
        "same source/destination port counts once"
    );
}

#[test]
fn stats_reject_zero_interval_and_empty_report_is_well_formed() {
    assert!(matches!(
        StatsCollector::new(Duration::ZERO),
        Err(Error::InvalidLimit {
            field: "interval",
            value: 0,
            ..
        })
    ));
    let report = StatsCollector::new(Duration::from_millis(250))
        .expect("valid interval")
        .finish();
    assert_eq!(report.frames, 0);
    assert_eq!(report.bytes, 0);
    assert!(report.first_timestamp.is_none());
    assert!(report.protocols.is_empty());
    assert!(report.conversations.is_empty());
    assert!(report.io.is_empty());
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
    let mut collector = FollowCollector::new(Selector {
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
    let summary = collector.finish(&run_summary.trailing_tcp_events);
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
    let mut collector = FollowCollector::new(Selector {
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
    let summary = collector.finish(&run_summary.trailing_tcp_events);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].bytes.as_ref(), b"query");
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[1].bytes.as_ref(), b"answer");
    assert_eq!(chunks[1].direction, FollowDirection::ServerToClient);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 5);
    assert_eq!(summary.server_bytes, 6);

    let empty = FollowCollector::new(Selector {
        transport: StreamTransport::Udp,
        index: 99,
    })
    .finish(&[]);
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
    let mut collector = FollowCollector::new(Selector {
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
    let summary = collector.finish(&run_summary.trailing_tcp_events);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 0);
    assert_eq!(summary.undelivered_bytes, 4);
}

#[test]
fn expert_combines_header_reassembly_and_end_of_capture_findings() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let mut frames = vec![
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 100), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 501, Tcp::ACK, 100),
            b"abc",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            server_tcp(501, 101, Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(4),
            server_tcp(501, 101, Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(5),
            client_tcp(104, 501, Tcp::ACK, 100),
            b"x",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(6),
            client_tcp(101, 501, Tcp::ACK, 100),
            b"abc",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(7),
            client_tcp(104, 501, Tcp::ACK, 100),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(8),
            server_tcp(501, 105, Tcp::ACK, 0),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(9),
            client_tcp(105, 501, Tcp::ACK, 100),
            b"z",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(10),
            client_tcp(106, 501, Tcp::RST | Tcp::ACK, 100),
            b"",
        ),
    ];
    frames.push(tcp_frame(
        &registry,
        epoch + Duration::from_secs(11),
        TcpSpec {
            source_port: 40_001,
            sequence: 1_000,
            ..client_tcp(0, 0, Tcp::SYN, 100)
        },
        b"",
    ));
    frames.push(tcp_frame(
        &registry,
        epoch + Duration::from_secs(12),
        TcpSpec {
            source_port: 40_001,
            sequence: 1_005,
            ..client_tcp(0, 0, Tcp::ACK, 100)
        },
        b"late",
    ));

    let mut capture = reader(&frames);
    let mut collector = ExpertCollector::new();
    let mut findings = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("expert pass succeeds");
    let (trailing, summary) =
        collector.finish(&run_summary.trailing_tcp_events, run_summary.frames_read);
    findings.extend(trailing);
    let codes = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "tcp.window_full",
        "tcp.duplicate_ack",
        "tcp.window_exceeded",
        "tcp.retransmission",
        "tcp.keep_alive",
        "tcp.zero_window",
        "tcp.zero_window_probe",
        "tcp.reset",
        "tcp.previous_segment_not_captured",
        "tcp.incomplete_at_end",
    ] {
        assert!(
            codes.contains(&expected),
            "missing expert finding {expected}: {codes:?}"
        );
    }
    assert_eq!(
        summary.findings,
        u64::try_from(findings.len()).expect("small fixture")
    );
    assert!(summary.warnings > 0);
    assert!(summary.notes > 0);
    assert_eq!(summary.codes.get("tcp.reset"), Some(&1));
    assert!(findings.iter().all(|finding| finding.number > 0));
    let incomplete = findings
        .iter()
        .find(|finding| finding.code == "tcp.incomplete_at_end")
        .expect("trailing finding exists");
    assert_eq!(
        incomplete.number,
        u64::try_from(frames.len()).expect("small fixture")
    );
    assert_eq!(incomplete.stream.expect("stream attribution").index, 1);
}

#[test]
fn analysis_errors_keep_policy_packet_and_boundary_classifications_distinct() {
    let invalid = Error::InvalidLimit {
        field: "max_flows",
        value: 0,
        reason: "must be non-zero",
    };
    assert_eq!(invalid.classification().kind, Kind::Cli);
    let stream = Error::StreamLimit {
        number: 2,
        limit: 1,
    };
    assert_eq!(stream.classification().kind, Kind::Policy);
    let malformed = Error::Reassembly {
        number: 3,
        source: tcp::Error::ConflictingFinalSequence {
            existing_offset: 1,
            new_offset: 2,
        },
    };
    assert_eq!(malformed.classification().kind, Kind::Packet);
    assert_eq!(malformed.causes().len(), 1);
    let bounded = Error::Reassembly {
        number: 3,
        source: tcp::Error::FlowByteLimit { limit: 8 },
    };
    assert_eq!(bounded.classification().kind, Kind::Policy);
    let sink = Error::Sink {
        number: 4,
        source: BoundaryError::execution_validation("bad sink", "test.sink", "repair it"),
    };
    assert_eq!(sink.classification().code, "test.sink");
    assert_eq!(sink.causes(), Vec::<String>::new());
}
