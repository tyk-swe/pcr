// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr::core::Packet;
use packetcraftr::core::analysis::expert::{
    Finding as AnalysisFinding, StreamRef, StreamTransport as AnalysisStreamTransport,
};
use packetcraftr::core::analysis::follow::{
    Chunk as AnalysisChunk, Direction as AnalysisDirection,
};
use packetcraftr::core::analysis::reassembly::tcp::FlowKey;
use packetcraftr::core::analysis::stats::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat, TransportKind,
};
use packetcraftr::core::diagnostic::Diagnostic;
use packetcraftr::core::frame::{Direction as CaptureDirection, Frame, LinkType};
use packetcraftr::core::layer::Raw;
use packetcraftr::core::protocol::{builtin, network::Ipv4, transport::Udp};
use packetcraftr::core::{build, decode};
use packetcraftr::output::{build as build_output, dissect as dissect_output};
use packetcraftr::output::{capture, contract, expert, follow, read, stats};
use serde_json::Value;

fn built_udp_packet() -> (
    Arc<packetcraftr::core::registry::Registry>,
    build::BuiltPacket,
) {
    let registry = Arc::new(builtin::registry().expect("built-ins must register"));
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 8_080,
        ..Udp::default()
    });
    packet.push(Raw::new(b"payload".to_vec()));
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, build::Context::default(), build::Options::default())
        .expect("representative packet must build");
    (registry, built)
}

#[test]
fn packet_output_adapters_preserve_wire_data_and_separate_diagnostics() {
    let (registry, mut built) = built_udp_packet();
    built
        .diagnostics
        .push(Diagnostic::warning("build.fixture", "fixture warning"));
    let wire = built.bytes.clone();
    let (built_output, build_diagnostics) = build_output::Result::from_built(built);

    assert_eq!(built_output.bytes(), wire.as_ref());
    assert_eq!(built_output.bytes_hex.len(), wire.len() * 2);
    assert_eq!(
        built_output.length,
        u64::try_from(wire.len()).expect("fixture length fits u64")
    );
    assert!(
        build_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.fixture")
    );
    assert!(
        serde_json::to_value(&built_output)
            .expect("build output serializes")
            .get("bytes")
            .is_none(),
        "raw bytes are exposed only through the byte accessor"
    );

    let mut frame = Frame::new(UNIX_EPOCH + Duration::from_secs(7), LinkType::IPV4, wire)
        .expect("built bytes form a capture frame");
    frame.interface = Some(3);
    frame.direction = Some(CaptureDirection::Inbound);
    let mut decoded = decode::Dissector::new(registry)
        .decode(frame.clone(), decode::Options::default())
        .expect("built packet must dissect");
    decoded
        .diagnostics
        .push(Diagnostic::info("decode.fixture", "fixture note"));

    assert!(matches!(
        read::Event::try_from_frame(0, frame.clone()),
        Err(contract::Error::InvalidSourceFrame)
    ));
    assert!(matches!(
        capture::Event::try_from_frame(0, frame.clone()),
        Err(contract::Error::InvalidSourceFrame)
    ));
    let raw_record = read::Event::try_from_frame(7, frame.clone()).expect("raw frame converts");
    let dissected_record =
        read::Event::try_from_decoded(7, frame, &decoded).expect("dissected frame converts");
    let raw_value = serde_json::to_value(&raw_record).expect("raw read event serializes");
    assert_eq!(raw_value["event"], "frame");
    assert_eq!(raw_value["source_frame"], 7);
    assert!(raw_value.get("decoded").is_none());
    let complete = serde_json::to_value(read::Event::Complete {
        frames_read: 7,
        frames_matched: 1,
        captured_bytes_read: 512,
    })
    .expect("read completion serializes");
    assert_eq!(complete["event"], "complete");
    assert_eq!(complete["captured_bytes_read"], 512);
    let read::Event::Frame {
        source_frame,
        frame: raw_frame,
        decoded: raw_decoded,
    } = raw_record
    else {
        panic!("raw conversion must produce a frame event")
    };
    let read::Event::Frame {
        source_frame: dissected_source_frame,
        frame: dissected_frame,
        decoded: decoded_stack,
    } = dissected_record
    else {
        panic!("dissected conversion must produce a frame event")
    };
    assert_eq!(source_frame.get(), 7);
    assert_eq!(dissected_source_frame.get(), 7);
    assert!(raw_decoded.is_none());
    assert_eq!(raw_frame.bytes(), dissected_frame.bytes());
    let stack = decoded_stack.expect("dissection was requested");
    assert_eq!(stack.layout, decoded.layout);
    assert!(
        stack
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.fixture")
    );

    let original = decoded.original.clone();
    let link_type = decoded.frame.link_type.0;
    let (dissected_output, decode_diagnostics) = dissect_output::Result::from_decoded(decoded);
    assert_eq!(dissected_output.bytes(), original.as_ref());
    assert_eq!(
        dissected_output.length,
        u64::try_from(original.len()).expect("fixture length fits u64")
    );
    assert_eq!(dissected_output.link_type, link_type);
    assert!(
        decode_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.fixture")
    );
}

fn representative_stats_report() -> packetcraftr::core::analysis::stats::Report {
    let first = UNIX_EPOCH + Duration::from_secs(5);
    let last = first + Duration::from_millis(3_250);
    packetcraftr::core::analysis::stats::Report {
        interval: Duration::from_secs(2),
        frames: 7,
        bytes: 321,
        first_timestamp: Some(first),
        last_timestamp: Some(last),
        protocols: vec![ProtocolStat {
            protocol: "ipv4".to_owned(),
            frames: 7,
            bytes: 321,
        }],
        conversations: vec![ConversationStat {
            transport: TransportKind::Tcp,
            stream: 4,
            address_a: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port_a: 40_000,
            address_b: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port_b: 443,
            frames_a_to_b: 3,
            bytes_a_to_b: 120,
            frames_b_to_a: 4,
            bytes_b_to_a: 201,
            first_timestamp: first,
            last_timestamp: last,
        }],
        endpoints: vec![EndpointStat {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            tx_frames: 3,
            tx_bytes: 120,
            rx_frames: 4,
            rx_bytes: 201,
        }],
        ports: vec![PortStat {
            transport: TransportKind::Udp,
            port: 53,
            frames: 2,
            bytes: 80,
        }],
        io: vec![IoBucketStat {
            offset: Duration::from_secs(2),
            frames: 5,
            bytes: 240,
        }],
    }
}

#[test]
fn stats_output_selects_exactly_one_requested_table() {
    let report = representative_stats_report();
    let cases = [
        (stats::Table::Conversations, "conversations"),
        (stats::Table::Endpoints, "endpoints"),
        (stats::Table::Protocols, "protocols"),
        (stats::Table::Ports, "ports"),
        (stats::Table::Io, "io"),
    ];

    for (table, expected_key) in cases {
        let result = stats::Result::try_from_report(table, &report, 9)
            .expect("in-range report must convert");
        let value = serde_json::to_value(&result).expect("statistics output serializes");

        assert_eq!(result.frames_read, 9);
        assert_eq!(result.frames_matched, 7);
        assert_eq!(result.bytes_matched, 321);
        assert_eq!(
            result
                .first_timestamp
                .expect("first timestamp")
                .unix_seconds,
            5
        );
        for key in ["conversations", "endpoints", "protocols", "ports", "io"] {
            assert_eq!(
                value.get(key).is_some(),
                key == expected_key,
                "table {table:?} leaked or omitted {key}"
            );
        }
    }
}

#[test]
fn stats_conversation_output_preserves_source_fields() {
    let report = representative_stats_report();
    let conversations = stats::Result::try_from_report(stats::Table::Conversations, &report, 9)
        .expect("conversation report converts")
        .conversations
        .expect("conversation table is present");
    let conversation = &conversations[0];
    assert_eq!(conversation.transport, stats::Transport::Tcp);
    assert_eq!(conversation.stream, 4);
    assert_eq!(
        conversation.address_a,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(conversation.port_a, 40_000);
    assert_eq!(
        conversation.address_b,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(conversation.port_b, 443);
    assert_eq!(
        (conversation.frames_a_to_b, conversation.bytes_a_to_b),
        (3, 120)
    );
    assert_eq!(
        (conversation.frames_b_to_a, conversation.bytes_b_to_a),
        (4, 201)
    );
    assert_eq!(conversation.duration, Duration::from_millis(3_250));
}

#[test]
fn stats_endpoint_output_preserves_source_fields() {
    let report = representative_stats_report();
    let endpoints = stats::Result::try_from_report(stats::Table::Endpoints, &report, 9)
        .expect("endpoint report converts")
        .endpoints
        .expect("endpoint table is present");
    assert_eq!(
        (
            endpoints[0].address,
            endpoints[0].tx_frames,
            endpoints[0].tx_bytes,
            endpoints[0].rx_frames,
            endpoints[0].rx_bytes,
        ),
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3, 120, 4, 201)
    );
}

#[test]
fn stats_protocol_output_preserves_source_fields() {
    let report = representative_stats_report();
    let protocols = stats::Result::try_from_report(stats::Table::Protocols, &report, 9)
        .expect("protocol report converts")
        .protocols
        .expect("protocol table is present");
    assert_eq!(
        (
            protocols[0].protocol.as_str(),
            protocols[0].frames,
            protocols[0].bytes
        ),
        ("ipv4", 7, 321)
    );
}

#[test]
fn stats_port_output_preserves_source_fields() {
    let report = representative_stats_report();
    let ports = stats::Result::try_from_report(stats::Table::Ports, &report, 9)
        .expect("port report converts")
        .ports
        .expect("port table is present");
    assert_eq!(
        (
            ports[0].transport,
            ports[0].port,
            ports[0].frames,
            ports[0].bytes
        ),
        (stats::Transport::Udp, 53, 2, 80)
    );
}

#[test]
fn stats_io_output_preserves_interval_and_buckets() {
    let report = representative_stats_report();
    let io = stats::Result::try_from_report(stats::Table::Io, &report, 9)
        .expect("I/O report converts")
        .io
        .expect("I/O table is present");
    assert_eq!(io.interval, Duration::from_secs(2));
    assert_eq!(
        (
            io.buckets[0].offset,
            io.buckets[0].frames,
            io.buckets[0].bytes
        ),
        (Duration::from_secs(2), 5, 240)
    );
}

#[test]
fn expert_output_preserves_finding_severity_streams_and_code_order() {
    let findings: Vec<expert::Finding> = [
        AnalysisFinding {
            severity: packetcraftr::core::diagnostic::Severity::Error,
            code: "tcp.reset".to_owned(),
            number: 8,
            stream: Some(StreamRef {
                transport: AnalysisStreamTransport::Tcp,
                index: 2,
            }),
            message: "connection reset".to_owned(),
        },
        AnalysisFinding {
            severity: packetcraftr::core::diagnostic::Severity::Warning,
            code: "udp.gap".to_owned(),
            number: 9,
            stream: Some(StreamRef {
                transport: AnalysisStreamTransport::Udp,
                index: 3,
            }),
            message: "datagram gap".to_owned(),
        },
        AnalysisFinding {
            severity: packetcraftr::core::diagnostic::Severity::Info,
            code: "capture.note".to_owned(),
            number: 10,
            stream: None,
            message: "capture note".to_owned(),
        },
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let expert_result = expert::Result::from_summary(
        packetcraftr::core::analysis::expert::Summary {
            findings: 3,
            errors: 1,
            warnings: 1,
            notes: 1,
            codes: BTreeMap::from([
                ("capture.note".to_owned(), 1),
                ("tcp.reset".to_owned(), 1),
                ("udp.gap".to_owned(), 1),
            ]),
        },
        12,
        11,
        findings,
    );
    let expert_json = serde_json::to_value(&expert_result).expect("expert output serializes");
    assert_eq!(expert_result.codes[0].code, "capture.note");
    assert_eq!(expert_json["findings"][0]["severity"], "error");
    assert_eq!(expert_json["findings"][0]["transport"], "tcp");
    assert_eq!(expert_json["findings"][1]["transport"], "udp");
    assert!(expert_json["findings"][2].get("stream").is_none());
    assert!(expert_json["findings"][2].get("transport").is_none());
}

#[test]
fn follow_output_preserves_flow_directions_bytes_and_missing_endpoints() {
    let flow = FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        source_port: 40_000,
        destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        destination_port: 443,
    };
    let chunks: Vec<follow::Chunk> = [
        AnalysisChunk {
            direction: AnalysisDirection::ClientToServer,
            number: 2,
            bytes: Bytes::from_static(&[0x00, 0xff]),
        },
        AnalysisChunk {
            direction: AnalysisDirection::ServerToClient,
            number: 3,
            bytes: Bytes::from_static(b"ok"),
        },
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let followed = follow::Result::from_summary(
        expert::StreamTransport::Tcp,
        2,
        packetcraftr::core::analysis::follow::Summary {
            client_flow: Some(flow),
            frames: 2,
            client_bytes: 2,
            server_bytes: 2,
            undelivered_bytes: 4,
        },
        chunks,
    );

    assert_eq!(followed.client.expect("client endpoint").port, 40_000);
    assert_eq!(followed.server.expect("server endpoint").port, 443);
    assert_eq!(followed.chunks[0].bytes_hex, "00ff");
    assert_eq!(followed.chunks[0].direction, follow::Direction::Client);
    assert_eq!(followed.chunks[1].direction, follow::Direction::Server);
    assert_eq!(followed.undelivered_bytes, 4);

    let empty = follow::Result::from_summary(
        expert::StreamTransport::Udp,
        99,
        packetcraftr::core::analysis::follow::Summary::default(),
        Vec::new(),
    );
    assert!(empty.client.is_none() && empty.server.is_none());
    assert_eq!(
        serde_json::to_value(empty).expect("empty follow output serializes")["chunks"],
        Value::Array(Vec::new())
    );
}
