// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::stream::StreamRecord;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_cli::output::{build as build_output, dissect as dissect_output};
use packetcraftr_cli::output::{capture, contract, expert, follow, read, stats};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::IpCounters;
use packetcraftr_core::analysis::IpDatagramOutcome;
use packetcraftr_core::analysis::IpFamilyCounters;
use packetcraftr_core::analysis::IpReassemblyReport;
use packetcraftr_core::analysis::StreamRef;
use packetcraftr_core::analysis::StreamTransport as AnalysisStreamTransport;
use packetcraftr_core::analysis::expert::Finding as AnalysisFinding;
use packetcraftr_core::analysis::follow::Chunk as AnalysisChunk;
use packetcraftr_core::analysis::follow::Direction as AnalysisDirection;
use packetcraftr_core::analysis::reassembly::ip::DatagramKey as AnalysisDatagramKey;
use packetcraftr_core::analysis::reassembly::ip::IncompleteDatagram;
use packetcraftr_core::analysis::reassembly::ip::IncompleteReason;
use packetcraftr_core::analysis::reassembly::ip::Ipv4DatagramKey as AnalysisIpv4DatagramKey;
use packetcraftr_core::analysis::reassembly::ip::Ipv6DatagramKey as AnalysisIpv6DatagramKey;
use packetcraftr_core::analysis::reassembly::tcp::FlowKey;
use packetcraftr_core::analysis::scope::Interner;
use packetcraftr_core::analysis::stats::ConversationStat;
use packetcraftr_core::analysis::stats::EndpointStat;
use packetcraftr_core::analysis::stats::IoBucketStat;
use packetcraftr_core::analysis::stats::PortStat;
use packetcraftr_core::analysis::stats::ProtocolStat;
use packetcraftr_core::build;
use packetcraftr_core::decode;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Direction as CaptureDirection;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use serde_json::Value;

fn built_udp_packet() -> (
    Arc<packetcraftr_core::registry::Registry>,
    build::BuiltPacket,
) {
    let registry = builtin::registry();
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
    let (built_output, build_diagnostics) = build_output::Report::from_built(built);

    assert_eq!(built_output.frame.bytes(), wire.as_ref());
    assert_eq!(
        built_output.frame.bytes_hex().to_string().len(),
        wire.len() * 2
    );
    assert_eq!(
        built_output.frame.length,
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
        read::Frame::try_from_frame(0, frame.clone()),
        Err(contract::Error::InvalidSourceFrame)
    ));
    assert!(matches!(
        capture::Event::try_from_frame(0, frame.clone()),
        Err(contract::Error::InvalidSourceFrame)
    ));
    let raw_record = read::Frame::try_from_frame(7, frame.clone()).expect("raw frame converts");
    let dissected_record =
        read::Frame::try_from_decoded(7, frame, &decoded).expect("dissected frame converts");
    let event = read::Event::Frame(raw_record.clone());
    assert_eq!(event.event_name(), "frame");
    let raw_value = serde_json::to_value(event).expect("raw read payload serializes");
    assert_eq!(raw_value["source_frame"], 7);
    assert!(raw_value.get("decoded").is_none());
    let complete = read::Event::Complete {
        frames_read: 7,
        frames_matched: 1,
        captured_bytes_read: 512,
    };
    assert_eq!(complete.event_name(), "complete");
    let complete = serde_json::to_value(complete).expect("read completion payload serializes");
    assert_eq!(complete["captured_bytes_read"], 512);
    let read::Frame {
        source_frame,
        frame: raw_frame,
        decoded: raw_decoded,
    } = raw_record;
    let read::Frame {
        source_frame: dissected_source_frame,
        frame: dissected_frame,
        decoded: decoded_stack,
    } = dissected_record;
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
    let (dissected_output, decode_diagnostics) = dissect_output::Report::from_decoded(decoded);
    assert_eq!(dissected_output.frame.bytes(), original.as_ref());
    assert_eq!(
        dissected_output.frame.length,
        u64::try_from(original.len()).expect("fixture length fits u64")
    );
    assert_eq!(dissected_output.link_type, link_type);
    assert!(
        decode_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.fixture")
    );
}

fn representative_stats_report() -> packetcraftr_core::analysis::stats::Report {
    let first = UNIX_EPOCH + Duration::from_secs(5);
    let last = first + Duration::from_millis(3_250);
    let mut scopes = Interner::new();
    let scope = scopes
        .intern(None, Vec::new())
        .expect("representative scope fits");
    packetcraftr_core::analysis::stats::Report {
        clock: Default::default(),
        io_origin: Some(first),
        io_underflow_frames: 0,
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
            scope: scopes.definition(scope).unwrap().clone(),
            transport: AnalysisStreamTransport::Tcp,
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
            transport: AnalysisStreamTransport::Udp,
            port: 53,
            frames: 2,
            bytes: 80,
        }],
        io: vec![IoBucketStat {
            offset: Duration::from_secs(2),
            frames: 5,
            bytes: 240,
        }],
        ip_reassembly: IpReassemblyReport {
            counters: IpCounters {
                ipv4: IpFamilyCounters {
                    physical_fragments: 3,
                    admitted_fragments: 3,
                    completing_fragments: 1,
                    completed_datagrams: 1,
                    overlap_bytes: 2,
                    derived_datagram_bytes: 44,
                    derived_payload_bytes: 24,
                    ..IpFamilyCounters::default()
                },
                ipv6: IpFamilyCounters {
                    physical_fragments: 1,
                    admitted_fragments: 1,
                    incomplete_datagrams: 1,
                    end_of_capture_datagrams: 1,
                    ..IpFamilyCounters::default()
                },
            },
            outcomes: vec![
                IpDatagramOutcome::Completed {
                    key: AnalysisDatagramKey::Ipv4(AnalysisIpv4DatagramKey {
                        scope,
                        source: Ipv4Addr::new(192, 0, 2, 1),
                        destination: Ipv4Addr::new(198, 51, 100, 2),
                        identification: 42,
                        protocol: 17,
                    }),
                    fragment_count: 3,
                    unique_bytes: 24,
                    final_payload_length: 24,
                    datagram_bytes: 44,
                    duplicate_fragments: 1,
                    overlap_bytes: 2,
                },
                IpDatagramOutcome::Incomplete(IncompleteDatagram {
                    key: AnalysisDatagramKey::Ipv6(AnalysisIpv6DatagramKey {
                        scope,
                        source: Ipv6Addr::LOCALHOST,
                        destination: "2001:db8::2".parse().expect("documentation address"),
                        identification: 7,
                    }),
                    reason: IncompleteReason::EndOfCapture,
                    fragment_count: 1,
                    unique_bytes: 16,
                    known_final_length: None,
                    duplicate_fragments: 0,
                    overlap_bytes: 0,
                }),
            ],
            outcomes_omitted: 2,
        },
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
        (stats::Table::Fragments, "fragments"),
    ];

    for (table, expected_key) in cases {
        let result = stats::Report::try_from_report(table, report.clone(), 9)
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
        for key in [
            "conversations",
            "endpoints",
            "protocols",
            "ports",
            "io",
            "fragments",
        ] {
            assert_eq!(
                value.get(key).is_some(),
                key == expected_key,
                "table {table:?} leaked or omitted {key}"
            );
        }
    }
}

#[test]
fn stats_fragment_output_preserves_family_counters_outcomes_and_omissions() {
    let report = representative_stats_report();
    let stats::TableData::Fragments { fragments } =
        stats::Report::try_from_report(stats::Table::Fragments, report.clone(), 9)
            .expect("fragment report converts")
            .table
    else {
        panic!("wrong table")
    };

    assert_eq!(fragments.families.len(), 2);
    assert_eq!(fragments.families[0].counters.physical_fragments, 3);
    assert_eq!(fragments.families[0].counters.completed_datagrams, 1);
    assert_eq!(fragments.families[0].counters.derived_datagram_bytes, 44);
    assert_eq!(fragments.families[0].counters.derived_payload_bytes, 24);
    assert_eq!(fragments.families[1].counters.incomplete_datagrams, 1);
    assert_eq!(fragments.families[1].counters.end_of_capture_datagrams, 1);
    assert_eq!(fragments.outcomes_omitted, 2);
    assert_eq!(fragments.outcomes.len(), 2);

    let value = serde_json::to_value(&fragments).expect("fragment output serializes");
    assert_eq!(value["families"][0]["family"], "ipv4");
    assert_eq!(value["families"][1]["family"], "ipv6");
    assert_eq!(value["outcomes"][0]["status"], "completed");
    assert_eq!(value["outcomes"][0]["key"]["family"], "ipv4");
    assert_eq!(value["outcomes"][0]["key"]["scope"], 0);
    assert_eq!(value["outcomes"][0]["key"]["protocol"], 17);
    assert_eq!(value["outcomes"][1]["status"], "incomplete");
    assert_eq!(value["outcomes"][1]["reason"], "end_of_capture");
    assert_eq!(value["outcomes"][1]["key"]["family"], "ipv6");
    assert!(value["outcomes"][1].get("known_final_length").is_none());
}

#[test]
fn stats_conversation_output_preserves_source_fields() {
    let report = representative_stats_report();
    let stats::TableData::Conversations { conversations } =
        stats::Report::try_from_report(stats::Table::Conversations, report.clone(), 9)
            .expect("conversation report converts")
            .table
    else {
        panic!("wrong table")
    };
    let conversation = &conversations[0];
    assert_eq!(
        conversation.transport,
        packetcraftr_core::analysis::StreamTransport::Tcp
    );
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
    let stats::TableData::Endpoints { endpoints } =
        stats::Report::try_from_report(stats::Table::Endpoints, report.clone(), 9)
            .expect("endpoint report converts")
            .table
    else {
        panic!("wrong table")
    };
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
    let stats::TableData::Protocols { protocols } =
        stats::Report::try_from_report(stats::Table::Protocols, report.clone(), 9)
            .expect("protocol report converts")
            .table
    else {
        panic!("wrong table")
    };
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
    let stats::TableData::Ports { ports } =
        stats::Report::try_from_report(stats::Table::Ports, report.clone(), 9)
            .expect("port report converts")
            .table
    else {
        panic!("wrong table")
    };
    assert_eq!(
        (
            ports[0].transport,
            ports[0].port,
            ports[0].frames,
            ports[0].bytes
        ),
        (packetcraftr_core::analysis::StreamTransport::Udp, 53, 2, 80)
    );
}

#[test]
fn stats_io_output_preserves_interval_and_buckets() {
    let report = representative_stats_report();
    let stats::TableData::Io { io } =
        stats::Report::try_from_report(stats::Table::Io, report.clone(), 9)
            .expect("I/O report converts")
            .table
    else {
        panic!("wrong table")
    };
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
            severity: packetcraftr_core::diagnostic::Severity::Error,
            code: "tcp.reset".to_owned(),
            number: 8,
            stream: Some(StreamRef {
                transport: AnalysisStreamTransport::Tcp,
                index: 2,
            }),
            message: "connection reset".to_owned(),
        },
        AnalysisFinding {
            severity: packetcraftr_core::diagnostic::Severity::Warning,
            code: "udp.gap".to_owned(),
            number: 9,
            stream: Some(StreamRef {
                transport: AnalysisStreamTransport::Udp,
                index: 3,
            }),
            message: "datagram gap".to_owned(),
        },
        AnalysisFinding {
            severity: packetcraftr_core::diagnostic::Severity::Info,
            code: "capture.note".to_owned(),
            number: 10,
            stream: None,
            message: "capture note".to_owned(),
        },
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let expert_result = expert::Report::from_summary(
        packetcraftr_core::analysis::expert::Summary {
            clock: Default::default(),
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
        &IpReassemblyReport::default(),
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
            direction_generation: 0,
            direction: AnalysisDirection::ClientToServer,
            number: 2,
            bytes: Bytes::from_static(&[0x00, 0xff]),
        },
        AnalysisChunk {
            direction_generation: 0,
            direction: AnalysisDirection::ServerToClient,
            number: 3,
            bytes: Bytes::from_static(b"ok"),
        },
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let followed = follow::Report::from_summary(
        packetcraftr_core::analysis::StreamTransport::Tcp,
        2,
        packetcraftr_core::analysis::follow::Summary {
            scope: None,
            clock: Default::default(),
            client_flow: Some(flow),
            frames: 2,
            client_bytes: 2,
            server_bytes: 2,
            undelivered_bytes: 4,
        },
        chunks,
        &IpReassemblyReport::default(),
    );

    assert_eq!(followed.client.expect("client endpoint").port, 40_000);
    assert_eq!(followed.server.expect("server endpoint").port, 443);
    assert_eq!(followed.chunks[0].bytes_hex, "00ff");
    assert_eq!(
        followed.chunks[0].direction,
        packetcraftr_core::analysis::follow::Direction::ClientToServer
    );
    assert_eq!(
        followed.chunks[1].direction,
        packetcraftr_core::analysis::follow::Direction::ServerToClient
    );
    assert_eq!(followed.undelivered_bytes, 4);

    let empty = follow::Report::from_summary(
        packetcraftr_core::analysis::StreamTransport::Udp,
        99,
        packetcraftr_core::analysis::follow::Summary::default(),
        Vec::new(),
        &IpReassemblyReport::default(),
    );
    assert!(empty.client.is_none() && empty.server.is_none());
    assert_eq!(
        serde_json::to_value(empty).expect("empty follow output serializes")["chunks"],
        Value::Array(Vec::new())
    );
}
