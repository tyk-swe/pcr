// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{
    CLIENT, SERVER, TcpSpec, client_tcp as client, reader, registry, server_tcp as server,
    tcp_frame as frame, udp_frame,
};
use packetcraftr_core::analysis::expert::Finding;
use packetcraftr_core::analysis::{Options, run};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};

use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::{Tcp, TcpOption};
use packetcraftr_core::registry::Registry;

fn with_window_scale(mut spec: TcpSpec, shift: u8) -> TcpSpec {
    spec.options = vec![TcpOption::WindowScale(shift), TcpOption::End];
    spec
}

fn analyze_frames(
    registry: Arc<Registry>,
    frames: &[Frame],
) -> (Vec<Finding>, packetcraftr_core::analysis::expert::Summary) {
    let mut capture = reader(frames);
    let mut collector = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    let run_summary = run(
        &mut capture,
        registry,
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
    (findings, summary)
}

fn analyze(
    segments: &[(TcpSpec, &[u8])],
) -> (Vec<Finding>, packetcraftr_core::analysis::expert::Summary) {
    let registry = registry();
    let frames = segments
        .iter()
        .enumerate()
        .map(|(index, (spec, payload))| {
            let timestamp = SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(index).expect("fixture index fits u64"));
            frame(&registry, timestamp, spec.clone(), payload)
        })
        .collect::<Vec<_>>();
    analyze_frames(registry, &frames)
}

fn finding(
    severity: packetcraftr_core::diagnostic::Severity,
    code: &'static str,
    number: u64,
    message: &str,
) -> Finding {
    Finding {
        severity,
        code,
        number,
        stream: Some(StreamRef {
            transport: StreamTransport::Tcp,
            index: 0,
        }),
        message: message.to_owned(),
    }
}

fn assert_expert(
    segments: &[(TcpSpec, &[u8])],
    expected: Vec<Finding>,
    errors: u64,
    warnings: u64,
    notes: u64,
) {
    let (actual, summary) = analyze(segments);
    assert_eq!(actual, expected);

    let mut codes = BTreeMap::new();
    for item in &expected {
        *codes.entry(item.code).or_default() += 1;
    }
    assert_eq!(
        summary,
        packetcraftr_core::analysis::expert::Summary {
            clock: summary.clock.clone(),
            findings: u64::try_from(expected.len()).expect("fixture count fits u64"),
            errors,
            warnings,
            notes,
            codes,
        }
    );
}

#[test]
fn duplicate_acknowledgments_require_outstanding_payload_and_keep_order() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 1_000), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b"abc"),
        (server(501, 101, Tcp::ACK, 1_000), b""),
        (server(501, 101, Tcp::ACK, 1_000), b""),
        (server(501, 104, Tcp::ACK, 1_000), b""),
        (server(501, 104, Tcp::ACK, 1_000), b""),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.duplicate_ack",
                5,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #1)",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.duplicate_ack",
                6,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #2)",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn duplicate_acknowledgment_requires_captured_reverse_payload() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
    ];

    assert_expert(&segments, Vec::new(), 0, 0, 0);
}

#[test]
fn unreportable_duplicate_acknowledgments_do_not_advance_the_count() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
        (server(2_000, 1_000, Tcp::ACK, 8_192), b"x"),
        (client(1_000, 2_000, Tcp::ACK, 8_192), b""),
    ];

    assert_expert(
        &segments,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Warning,
            "tcp.duplicate_ack",
            5,
            "192.0.2.1:40000 repeats acknowledgment 2000 (duplicate #1)",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn keep_alive_and_zero_window_probe_shapes_remain_distinct() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b"a"),
        (server(501, 102, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (server(501, 102, Tcp::ACK, 0), b""),
        (client(102, 501, Tcp::ACK, 100), b"z"),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Info,
                "tcp.keep_alive",
                6,
                "192.0.2.1:40000 probes the peer",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.zero_window",
                7,
                "198.51.100.2:443 advertises a zero receive window",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Info,
                "tcp.zero_window_probe",
                8,
                "192.0.2.1:40000 probes the peer's zero receive window",
            ),
        ],
        0,
        1,
        2,
    );
}

#[test]
fn one_byte_keep_alive_suppresses_overlap_retransmission() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b"a"),
        (server(501, 102, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b"z"),
    ];
    assert_expert(
        &segments,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Info,
            "tcp.keep_alive",
            6,
            "192.0.2.1:40000 probes the peer",
        )],
        0,
        0,
        1,
    );
}

#[test]
fn gap_retransmission_conflict_and_end_residue_have_exact_attribution() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 1_000), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b""),
        (client(101, 501, Tcp::ACK, 1_000), b"abc"),
        (client(106, 501, Tcp::ACK, 1_000), b"xy"),
        (client(101, 501, Tcp::ACK, 1_000), b"abc"),
        (client(101, 501, Tcp::ACK, 1_000), b"abd"),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.previous_segment_not_captured",
                5,
                "192.0.2.1:40000 resumes at sequence 106 before sequence 104 arrived",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.retransmission",
                6,
                "3 byte(s) at sequence 101 retransmit previously seen data",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Error,
                "tcp.retransmission_conflicting",
                7,
                "3 byte(s) at sequence 101 retransmit previously seen data with different content",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Info,
                "tcp.incomplete_at_end",
                7,
                "2 byte(s) from 192.0.2.1:40000 were still awaiting missing earlier data when the capture ended",
            ),
        ],
        1,
        2,
        1,
    );
}

#[test]
fn unscaled_window_full_and_exceeded_findings_are_exact() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 3), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b"abc"),
        (client(104, 501, Tcp::ACK, 100), b"d"),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.window_full",
                4,
                "192.0.2.1:40000 has filled the peer's 3-byte receive window",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.window_exceeded",
                5,
                "192.0.2.1:40000 has sent 1 byte(s) beyond the peer's 3-byte receive window",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn negotiated_window_scale_applies_only_after_the_syn_window() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (with_window_scale(client(100, 0, Tcp::SYN, 100), 2), b""),
        (
            with_window_scale(server(500, 101, Tcp::SYN | Tcp::ACK, 2), 2),
            b"",
        ),
        (client(101, 501, Tcp::ACK, 100), b""),
        (server(501, 101, Tcp::ACK, 2), b""),
        (client(101, 501, Tcp::ACK, 100), b"abcdefgh"),
        (client(109, 501, Tcp::ACK, 100), b"i"),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.window_full",
                5,
                "192.0.2.1:40000 has filled the peer's 8-byte receive window",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.window_exceeded",
                6,
                "192.0.2.1:40000 has sent 1 byte(s) beyond the peer's 8-byte receive window",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn reordered_window_update_does_not_replace_the_newer_advertisement() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 10), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (server(502, 101, Tcp::ACK, 5), b""),
        (server(501, 101, Tcp::ACK, 1), b""),
        (client(101, 501, Tcp::ACK, 100), b"abcde"),
    ];
    assert_expert(
        &segments,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Warning,
            "tcp.window_full",
            6,
            "192.0.2.1:40000 has filled the peer's 5-byte receive window",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn clean_close_produces_no_expert_findings() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""),
        (server(501, 102, Tcp::ACK, 100), b""),
        (server(501, 102, Tcp::FIN | Tcp::ACK, 100), b""),
        (client(102, 502, Tcp::ACK, 100), b""),
    ];
    assert_expert(&segments, Vec::new(), 0, 0, 0);
}

#[test]
fn clean_close_applies_after_gap_fill_and_covers_late_retransmission() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(104, 501, Tcp::FIN | Tcp::ACK, 100), b"def"),
        (client(101, 501, Tcp::ACK, 100), b"abc"),
        (client(101, 501, Tcp::ACK, 100), b"abc"),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.previous_segment_not_captured",
                4,
                "192.0.2.1:40000 resumes at sequence 104 before sequence 101 arrived",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.retransmission",
                6,
                "3 byte(s) at sequence 101 retransmit previously seen data",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn non_tcp_sweep_retires_expired_expert_generation() {
    let registry = registry();
    let timestamp = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    let frames = vec![
        frame(&registry, timestamp(0), client(100, 0, Tcp::SYN, 100), b""),
        frame(
            &registry,
            timestamp(1),
            server(500, 101, Tcp::SYN | Tcp::ACK, 100),
            b"",
        ),
        frame(
            &registry,
            timestamp(2),
            client(101, 501, Tcp::ACK, 100),
            b"",
        ),
        frame(
            &registry,
            timestamp(3),
            client(101, 501, Tcp::ACK, 100),
            b"abc",
        ),
        frame(
            &registry,
            timestamp(4),
            client(104, 501, Tcp::FIN | Tcp::ACK, 100),
            b"",
        ),
        frame(
            &registry,
            timestamp(5),
            client(105, 501, Tcp::ACK, 100),
            b"def",
        ),
        udp_frame(&registry, timestamp(126), CLIENT, SERVER, 53_000, 53, b""),
        frame(
            &registry,
            timestamp(127),
            client(105, 501, Tcp::ACK, 100),
            b"ghi",
        ),
    ];

    let (findings, summary) = analyze_frames(registry, &frames);
    assert!(findings.is_empty());
    assert_eq!(
        summary.clock.max_forward_step,
        std::time::Duration::from_secs(121)
    );
    assert_eq!(summary.clock.max_forward_step_frame, Some(7));
    assert_eq!(
        summary,
        packetcraftr_core::analysis::expert::Summary {
            clock: summary.clock.clone(),
            ..Default::default()
        }
    );
}

#[test]
fn reset_is_attributed_before_state_is_retired() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (server(501, 101, Tcp::RST | Tcp::ACK, 100), b""),
    ];
    assert_expert(
        &segments,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Warning,
            "tcp.reset",
            4,
            "connection reset by 198.51.100.2:443",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn renewed_syn_clears_stale_tuple_window_state() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (server(501, 101, Tcp::ACK, 0), b""),
        (client(1_000, 0, Tcp::SYN, 100), b""),
        (server(2_000, 1_001, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(1_001, 2_001, Tcp::ACK, 100), b""),
        (client(1_001, 2_001, Tcp::ACK, 100), b"abcd"),
    ];
    assert_expert(
        &segments,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Warning,
            "tcp.zero_window",
            4,
            "198.51.100.2:443 advertises a zero receive window",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn capture_evidence_surfaces_truncated_frames_and_clock_regressions() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let full = udp_frame(
        &registry,
        epoch + Duration::from_secs(10),
        CLIENT,
        SERVER,
        1_000,
        9_999,
        b"first",
    );
    let truncated = {
        let frame = udp_frame(
            &registry,
            epoch + Duration::from_secs(11),
            SERVER,
            CLIENT,
            9_999,
            1_000,
            b"second-payload",
        );
        // Simulate a snaplen-truncated record: fewer captured bytes than the
        // wire length the frame declares.
        let cut = frame.captured_length() - 6;
        Frame::try_with_lengths(
            epoch + Duration::from_secs(11),
            frame.link_type,
            cut,
            frame.captured_length(),
            frame.bytes().slice(..cut as usize),
        )
        .expect("truncated fixture frame is valid")
    };
    let regressed = udp_frame(
        &registry,
        epoch + Duration::from_secs(1),
        CLIENT,
        SERVER,
        1_000,
        9_999,
        b"third",
    );
    let (findings, _summary) = analyze_frames(registry, &[full, truncated, regressed]);

    let truncated_finding = findings
        .iter()
        .find(|finding| finding.code == "capture.frame_truncated")
        .expect("truncated frame produces a finding");
    assert_eq!(
        truncated_finding.severity,
        packetcraftr_core::diagnostic::Severity::Warning
    );
    assert_eq!(truncated_finding.number, 2);
    assert!(truncated_finding.stream.is_none());
    assert!(truncated_finding.message.contains("of "));

    let regression_finding = findings
        .iter()
        .find(|finding| finding.code == "capture.clock_regression")
        .expect("regressed timestamp produces a finding");
    assert_eq!(
        regression_finding.severity,
        packetcraftr_core::diagnostic::Severity::Warning
    );
    assert_eq!(regression_finding.number, 3);
    assert!(regression_finding.message.contains("10s"));
}

#[test]
fn capture_evidence_stays_silent_on_well_formed_ordered_captures() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(&registry, epoch, CLIENT, SERVER, 1_000, 9_999, b"a"),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            SERVER,
            CLIENT,
            9_999,
            1_000,
            b"b",
        ),
    ];
    let (findings, _summary) = analyze_frames(registry, &frames);
    assert!(
        findings
            .iter()
            .all(|finding| !finding.code.starts_with("capture.")),
        "clean capture produced capture evidence: {findings:?}"
    );
}

#[test]
fn capture_evidence_combines_on_one_frame() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let full = udp_frame(
        &registry,
        epoch + Duration::from_secs(10),
        CLIENT,
        SERVER,
        1_000,
        9_999,
        b"high-water",
    );
    let combined = {
        let frame = udp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            SERVER,
            CLIENT,
            9_999,
            1_000,
            b"truncated-and-late",
        );
        let cut = frame.captured_length() - 4;
        Frame::try_with_lengths(
            epoch + Duration::from_secs(2),
            frame.link_type,
            cut,
            frame.captured_length(),
            frame.bytes().slice(..cut as usize),
        )
        .expect("truncated fixture frame is valid")
    };
    let (findings, _summary) = analyze_frames(registry, &[full, combined]);
    let codes: Vec<_> = findings
        .iter()
        .filter(|finding| finding.number == 2)
        .map(|finding| finding.code)
        .collect();
    assert!(codes.contains(&"capture.frame_truncated"), "{codes:?}");
    assert!(codes.contains(&"capture.clock_regression"), "{codes:?}");
}

#[test]
fn capture_evidence_names_the_declared_interface_when_present() {
    use packetcraftr_core::analysis::pcap::{Reader, Writer};
    use std::io::Cursor;

    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let truncated = {
        let frame = udp_frame(
            &registry,
            epoch,
            CLIENT,
            SERVER,
            1_000,
            9_999,
            b"payload-cut-short",
        );
        let cut = frame.captured_length() - 4;
        Frame::try_with_lengths(
            epoch,
            frame.link_type,
            cut,
            frame.captured_length(),
            frame.bytes().slice(..cut as usize),
        )
        .expect("truncated fixture frame is valid")
    };
    let mut writer = Writer::pcapng(Vec::new()).expect("pcapng writer initializes");
    writer
        .write_frame(&truncated)
        .expect("pcapng frame writes with an interface description");
    let mut regressed = truncated.clone();
    regressed.timestamp = Some(SystemTime::UNIX_EPOCH);
    writer.write_frame(&regressed).unwrap();
    let mut capture = Reader::new(Cursor::new(writer.into_inner())).expect("pcapng fixture opens");

    let mut collector = packetcraftr_core::analysis::expert::Collector::new();
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
    let _ = collector.finish(&run_summary);
    let finding = findings
        .iter()
        .find(|finding| finding.code == "capture.frame_truncated")
        .expect("truncated frame produces a finding");
    assert_eq!(finding.number, 1);
    assert!(
        finding.message.contains("on interface 0"),
        "{:?}",
        finding.message
    );
    let regression = findings
        .iter()
        .find(|finding| finding.code == "capture.clock_regression")
        .expect("regressed frame produces a finding");
    assert_eq!(regression.number, 2);
    assert!(regression.message.contains("on interface 0"));
}
