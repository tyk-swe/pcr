// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame};
use packetcraftr_core::analysis::expert::Collector;
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::analysis::{Error, Options, run};
use packetcraftr_core::error::{BoundaryError, Classified, Kind};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

fn expert_frames(registry: &Arc<Registry>, epoch: SystemTime) -> Vec<Frame> {
    let mut frames = vec![
        tcp_frame(registry, epoch, client_tcp(100, 0, Tcp::SYN, 100), b""),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 501, Tcp::ACK, 100),
            b"abc",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(3),
            server_tcp(501, 101, Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(4),
            server_tcp(501, 101, Tcp::ACK, 3),
            b"",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(5),
            client_tcp(104, 501, Tcp::ACK, 100),
            b"x",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(6),
            client_tcp(101, 501, Tcp::ACK, 100),
            b"abc",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(7),
            client_tcp(104, 501, Tcp::ACK, 100),
            b"",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(8),
            server_tcp(501, 105, Tcp::ACK, 0),
            b"",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(9),
            client_tcp(105, 501, Tcp::ACK, 100),
            b"z",
        ),
        tcp_frame(
            registry,
            epoch + Duration::from_secs(10),
            client_tcp(106, 501, Tcp::RST | Tcp::ACK, 100),
            b"",
        ),
    ];
    frames.push(tcp_frame(
        registry,
        epoch + Duration::from_secs(11),
        TcpSpec {
            source_port: 40_001,
            sequence: 1_000,
            ..client_tcp(0, 0, Tcp::SYN, 100)
        },
        b"",
    ));
    frames.push(tcp_frame(
        registry,
        epoch + Duration::from_secs(12),
        TcpSpec {
            source_port: 40_001,
            sequence: 1_005,
            ..client_tcp(0, 0, Tcp::ACK, 100)
        },
        b"late",
    ));
    frames
}

#[test]
fn expert_combines_header_reassembly_and_end_of_capture_findings() {
    let _udp_fixture = common::udp_frame;
    let registry = registry();
    let frames = expert_frames(&registry, SystemTime::UNIX_EPOCH);
    let mut capture = reader(&frames);
    let mut collector = Collector::new();
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
    let (trailing, summary) = collector.finish(&run_summary);
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
        source: tcp::MalformedError::ConflictingFinalSequence {
            existing_offset: 1,
            new_offset: 2,
        }
        .into(),
    };
    assert_eq!(malformed.classification().kind, Kind::Packet);
    assert_eq!(malformed.causes().len(), 1);
    let bounded = Error::Reassembly {
        number: 3,
        source: tcp::ResourceError::FlowByteLimit { limit: 8 }.into(),
    };
    assert_eq!(bounded.classification().kind, Kind::Policy);
    let tcp_remediation = bounded
        .classification()
        .remediation
        .expect("TCP resource failures have remediation");
    assert!(tcp_remediation.contains("trim or pre-filter the capture"));
    // A TCP budget failure must point at the TCP budgets, not tell the
    // operator to inspect the flow instead of raising them.
    assert!(tcp_remediation.contains("--max-tcp-*"));
    let bounded_ip = Error::IpReassembly {
        number: 3,
        source: packetcraftr_core::analysis::reassembly::ip::ResourceError::AggregateMemoryLimit {
            limit: 8,
        }
        .into(),
    };
    let remediation = bounded_ip
        .classification()
        .remediation
        .expect("IP resource failures have remediation");
    assert!(remediation.contains("trim or pre-filter the capture"));
    assert!(remediation.contains("--max-ip-*"));
    // An engine invariant that broke is neither the operator's capture nor
    // their budget, so it must not be reported as either.
    let inconsistent = Error::IpReassembly {
        number: 4,
        source: packetcraftr_core::analysis::reassembly::ip::Error::Inconsistent {
            reason: "retained datagram family disagrees with its key",
        },
    };
    assert_eq!(inconsistent.classification().kind, Kind::Internal);
    assert_eq!(inconsistent.classification().code, "internal.ip_reassembly");
    let bounded_scope = Error::Scope {
        number: 3,
        source: packetcraftr_core::analysis::scope::Error::Limit { limit: 8 },
    };
    assert_eq!(bounded_scope.classification().kind, Kind::Policy);
    for source in [
        packetcraftr_core::analysis::scope::Error::Unknown { scope: 7 },
        packetcraftr_core::analysis::scope::Error::ReplayMismatch { scope: 7 },
    ] {
        let invariant = Error::Scope { number: 3, source };
        assert_eq!(invariant.classification().kind, Kind::Internal);
        assert_eq!(
            invariant.classification().code,
            "internal.scope_composition"
        );
    }
    let sink = Error::Sink {
        number: 4,
        source: BoundaryError::execution_validation("bad sink", "test.sink", "repair it"),
    };
    assert_eq!(sink.classification().code, "test.sink");
    assert_eq!(sink.causes(), Vec::<String>::new());
}
