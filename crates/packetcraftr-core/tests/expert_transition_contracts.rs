// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{
    CLIENT, SERVER, TcpSpec, client_tcp as client, reader, registry, server_tcp as server,
    tcp_frame as frame, udp_frame,
};
use packetcraftr_core::analysis::expert::Finding;
use packetcraftr_core::analysis::{Options, run};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::diagnostic::Severity;

use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::protocol::transport::{Tcp, TcpOption};
use packetcraftr_core::registry::Registry;

fn with_window_scale(mut spec: TcpSpec, shift: u8) -> TcpSpec {
    spec.options = vec![TcpOption::WindowScale(shift), TcpOption::End];
    spec
}

fn analyze_capture(
    registry: Arc<Registry>,
    mut capture: Reader<impl Read>,
) -> (Vec<Finding>, packetcraftr_core::analysis::expert::Summary) {
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
    analyze_capture(registry, reader(&frames))
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

fn not_closed(number: u64) -> Finding {
    finding(
        packetcraftr_core::diagnostic::Severity::Info,
        "tcp.not_closed_at_end",
        number,
        "the connection opened by 192.0.2.1:40000 never saw a FIN or RST",
    )
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
            not_closed(8),
        ],
        0,
        2,
        1,
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
            not_closed(8),
        ],
        0,
        1,
        3,
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
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Info,
                "tcp.keep_alive",
                6,
                "192.0.2.1:40000 probes the peer",
            ),
            not_closed(6),
        ],
        0,
        0,
        2,
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
            not_closed(5),
        ],
        0,
        2,
        1,
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
            not_closed(6),
        ],
        0,
        2,
        1,
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
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.window_full",
                6,
                "192.0.2.1:40000 has filled the peer's 5-byte receive window",
            ),
            not_closed(6),
        ],
        0,
        1,
        1,
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
                "tcp.out_of_order",
                5,
                "192.0.2.1:40000 delivers the missing segment at sequence 101 after later data",
            ),
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.retransmission",
                6,
                "3 byte(s) at sequence 101 retransmit previously seen data",
            ),
        ],
        0,
        3,
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

    let (findings, summary) = analyze_capture(registry, reader(&frames));
    // Only the data sent before the sweep follows the FIN; frame 8 meets retired state.
    assert_eq!(
        findings,
        vec![finding(
            packetcraftr_core::diagnostic::Severity::Warning,
            "tcp.data_after_close",
            6,
            "192.0.2.1:40000 sent 3 byte(s) at sequence 105 after its FIN at sequence 104",
        )]
    );
    assert_eq!(
        summary.clock.max_forward_step,
        std::time::Duration::from_secs(121)
    );
    assert_eq!(summary.clock.max_forward_step_frame, Some(7));
    assert_eq!(
        summary,
        packetcraftr_core::analysis::expert::Summary {
            clock: summary.clock.clone(),
            findings: 1,
            warnings: 1,
            codes: BTreeMap::from([("tcp.data_after_close", 1)]),
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
        vec![
            finding(
                packetcraftr_core::diagnostic::Severity::Warning,
                "tcp.zero_window",
                4,
                "198.51.100.2:443 advertises a zero receive window",
            ),
            not_closed(8),
        ],
        0,
        1,
        1,
    );
}

fn capture_warning(code: &'static str, number: u64, message: &str) -> Finding {
    Finding {
        severity: packetcraftr_core::diagnostic::Severity::Warning,
        code,
        number,
        stream: None,
        message: message.to_owned(),
    }
}

fn capture_findings(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| finding.code.starts_with("capture."))
        .collect()
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
    let truncated = common::truncated(
        &udp_frame(
            &registry,
            epoch + Duration::from_secs(11),
            SERVER,
            CLIENT,
            9_999,
            1_000,
            b"second-payload",
        ),
        6,
    );
    let regressed = udp_frame(
        &registry,
        epoch + Duration::from_secs(1),
        CLIENT,
        SERVER,
        1_000,
        9_999,
        b"third",
    );
    let (findings, _summary) = analyze_capture(registry, reader(&[full, truncated, regressed]));

    assert_eq!(
        capture_findings(findings),
        vec![
            capture_warning(
                "capture.frame_truncated",
                2,
                "frame 2 captured 36 of 42 bytes",
            ),
            capture_warning(
                "capture.clock_regression",
                3,
                "frame 3 timestamp regressed 10s below the capture's latest observed timestamp",
            ),
        ]
    );
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
    let (findings, _summary) = analyze_capture(registry, reader(&frames));
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
    let combined = common::truncated(
        &udp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            SERVER,
            CLIENT,
            9_999,
            1_000,
            b"truncated-and-late",
        ),
        4,
    );
    let (findings, _summary) = analyze_capture(registry, reader(&[full, combined]));

    assert_eq!(
        capture_findings(findings),
        vec![
            capture_warning(
                "capture.frame_truncated",
                2,
                "frame 2 captured 42 of 46 bytes",
            ),
            capture_warning(
                "capture.clock_regression",
                2,
                "frame 2 timestamp regressed 8s below the capture's latest observed timestamp",
            ),
        ]
    );
}

#[test]
fn capture_evidence_names_the_declared_interface_when_present() {
    use packetcraftr_core::capture_file::Writer;
    use std::io::Cursor;

    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let truncated = common::truncated(
        &udp_frame(
            &registry,
            epoch,
            CLIENT,
            SERVER,
            1_000,
            9_999,
            b"payload-cut-short",
        ),
        4,
    );
    let mut writer = Writer::pcapng(Vec::new()).expect("pcapng writer initializes");
    writer
        .write_frame(&truncated)
        .expect("pcapng frame writes with an interface description");
    let mut regressed = truncated.clone();
    regressed.timestamp = Some(SystemTime::UNIX_EPOCH);
    writer.write_frame(&regressed).unwrap();
    let capture = Reader::new(Cursor::new(writer.into_inner())).expect("pcapng fixture opens");

    let (findings, _summary) = analyze_capture(registry, capture);

    assert_eq!(
        capture_findings(findings),
        vec![
            capture_warning(
                "capture.frame_truncated",
                1,
                "frame 1 captured 41 of 45 bytes on interface 0",
            ),
            capture_warning(
                "capture.frame_truncated",
                2,
                "frame 2 captured 41 of 45 bytes on interface 0",
            ),
            capture_warning(
                "capture.clock_regression",
                2,
                "frame 2 timestamp regressed 1s below the capture's latest observed timestamp on interface 0",
            ),
        ]
    );
}

fn codes_and_numbers(findings: &[Finding]) -> Vec<(&'static str, u64)> {
    findings
        .iter()
        .map(|finding| (finding.code, finding.number))
        .collect()
}

fn established() -> Vec<(TcpSpec, &'static [u8])> {
    vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
    ]
}

#[test]
fn repeated_syn_is_retransmitted_and_unanswered_at_the_end() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (client(100, 0, Tcp::SYN, 100), b""),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                Severity::Warning,
                "tcp.syn_retransmission",
                2,
                "192.0.2.1:40000 resends the SYN with initial sequence 100",
            ),
            finding(
                Severity::Warning,
                "tcp.handshake_unanswered",
                2,
                "the SYN from 192.0.2.1:40000 never received a SYN-ACK",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn syn_with_a_new_sequence_is_not_a_retransmission() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (client(900, 0, Tcp::SYN, 100), b""),
    ];
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.handshake_unanswered", 2)]
    );
}

#[test]
fn reset_answering_a_syn_is_a_refusal_instead_of_a_reset() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(0, 101, Tcp::RST | Tcp::ACK, 0), b""),
    ];
    assert_expert(
        &segments,
        vec![finding(
            Severity::Warning,
            "tcp.connection_refused",
            2,
            "198.51.100.2:443 reset the SYN exchanged with 192.0.2.1:40000",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn reset_answering_a_syn_ack_is_a_refusal() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 0, Tcp::RST, 0), b""),
    ];
    assert_expert(
        &segments,
        vec![finding(
            Severity::Warning,
            "tcp.connection_refused",
            3,
            "192.0.2.1:40000 reset the SYN-ACK exchanged with 198.51.100.2:443",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn resets_that_answer_no_handshake_stay_generic() {
    let mid_stream: Vec<(TcpSpec, &[u8])> = vec![
        (client(101, 501, Tcp::ACK, 100), b"abc"),
        (server(501, 104, Tcp::RST | Tcp::ACK, 0), b""),
    ];
    let (findings, _) = analyze(&mid_stream);
    assert_eq!(codes_and_numbers(&findings), [("tcp.reset", 2)]);

    let own_syn: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (client(101, 0, Tcp::RST, 0), b""),
    ];
    let (findings, _) = analyze(&own_syn);
    assert_eq!(codes_and_numbers(&findings), [("tcp.reset", 2)]);

    let stray_acknowledgment: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(0, 9_999, Tcp::RST | Tcp::ACK, 0), b""),
    ];
    let (findings, _) = analyze(&stray_acknowledgment);
    assert_eq!(codes_and_numbers(&findings), [("tcp.reset", 2)]);
}

#[test]
fn syn_ack_acknowledging_the_wrong_sequence_is_a_mismatch() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 105, Tcp::SYN | Tcp::ACK, 100), b""),
    ];
    assert_expert(
        &segments,
        vec![
            finding(
                Severity::Warning,
                "tcp.synack_mismatch",
                2,
                "198.51.100.2:443 acknowledges sequence 105 (+4 from the 101 the SYN from 192.0.2.1:40000 expects)",
            ),
            finding(
                Severity::Warning,
                "tcp.handshake_unanswered",
                2,
                "the SYN from 192.0.2.1:40000 never received a SYN-ACK",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn mismatched_syn_ack_leaves_the_syn_pending_for_a_correct_answer() {
    let mut segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 105, Tcp::SYN | Tcp::ACK, 100), b""),
        (server(700, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 701, Tcp::ACK, 100), b""),
    ];
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.synack_mismatch", 2), ("tcp.not_closed_at_end", 4)]
    );

    segments.truncate(2);
    segments.push((client(101, 0, Tcp::RST, 0), b""));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.synack_mismatch", 2), ("tcp.reset", 3)]
    );
}

#[test]
fn reset_and_syn_ack_after_idle_expiry_are_judged_against_the_expired_syn() {
    let registry = registry();
    let timestamp = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    let syn = || frame(&registry, timestamp(0), client(100, 0, Tcp::SYN, 100), b"");

    let reset = [
        syn(),
        frame(
            &registry,
            timestamp(200),
            server(0, 101, Tcp::RST | Tcp::ACK, 0),
            b"",
        ),
    ];
    let (findings, _) = analyze_capture(registry.clone(), reader(&reset));
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.connection_refused", 2)]
    );

    let mismatch = [
        syn(),
        frame(
            &registry,
            timestamp(200),
            server(500, 999, Tcp::SYN | Tcp::ACK, 100),
            b"",
        ),
    ];
    let (findings, _) = analyze_capture(registry, reader(&mismatch));
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.synack_mismatch", 2), ("tcp.handshake_unanswered", 2)]
    );
}

#[test]
fn syn_ack_matching_uses_serial_arithmetic_and_allows_syn_data() {
    let wrapped: Vec<(TcpSpec, &[u8])> = vec![
        (client(u32::MAX, 0, Tcp::SYN, 100), b""),
        (server(500, 0, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(0, 501, Tcp::ACK, 100), b""),
        (client(0, 501, Tcp::ACK, 100), b"abc"),
        (server(501, 3, Tcp::ACK, 100), b""),
    ];
    let (findings, _) = analyze(&wrapped);
    assert_eq!(codes_and_numbers(&findings), [("tcp.not_closed_at_end", 5)]);

    let syn_data: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b"abc"),
        (server(500, 104, Tcp::SYN | Tcp::ACK, 100), b""),
    ];
    let (findings, _) = analyze(&syn_data);
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn established_connection_without_a_close_is_noted_at_the_end() {
    let mut open = established();
    open.push((client(101, 501, Tcp::ACK, 100), b"abc"));
    open.push((server(501, 104, Tcp::ACK, 100), b""));
    assert_expert(&open, vec![not_closed(5)], 0, 0, 1);

    let mut closed = established();
    closed.push((client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""));
    closed.push((server(501, 102, Tcp::ACK, 100), b""));
    assert_expert(&closed, Vec::new(), 0, 0, 0);
}

#[test]
fn unclosed_connection_with_residue_reports_only_the_incomplete_end() {
    let mut segments = established();
    segments.push((client(106, 501, Tcp::ACK, 100), b"xy"));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.previous_segment_not_captured", 4),
            ("tcp.incomplete_at_end", 4)
        ]
    );
}

#[test]
fn syn_reusing_a_closed_tuple_inherits_no_handshake_state() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(100, 0, Tcp::SYN, 100), b""),
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::ACK, 100), b""),
        (client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""),
        (server(501, 102, Tcp::ACK, 100), b""),
        (server(501, 102, Tcp::FIN | Tcp::ACK, 100), b""),
        (client(102, 502, Tcp::ACK, 100), b""),
        (client(100, 0, Tcp::SYN, 100), b""),
    ];
    assert_expert(
        &segments,
        vec![finding(
            Severity::Warning,
            "tcp.handshake_unanswered",
            8,
            "the SYN from 192.0.2.1:40000 never received a SYN-ACK",
        )],
        0,
        1,
        0,
    );
}

#[test]
fn flows_evicted_before_the_end_report_no_handshake_findings() {
    let registry = registry();
    let timestamp = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    let frames = vec![
        frame(&registry, timestamp(0), client(100, 0, Tcp::SYN, 100), b""),
        udp_frame(&registry, timestamp(126), CLIENT, SERVER, 53_000, 53, b""),
    ];
    let (findings, _) = analyze_capture(registry, reader(&frames));
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn handshake_findings_follow_stream_order() {
    let registry = registry();
    let frames = [
        frame(
            &registry,
            SystemTime::UNIX_EPOCH,
            TcpSpec {
                source_port: 40_001,
                ..client(200, 0, Tcp::SYN, 100)
            },
            b"",
        ),
        frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            client(100, 0, Tcp::SYN, 100),
            b"",
        ),
    ];
    let (findings, _) = analyze_capture(registry, reader(&frames));
    let streams = findings
        .iter()
        .map(|finding| finding.stream.map(|stream| stream.index))
        .collect::<Vec<_>>();
    assert_eq!(streams, [Some(0), Some(1)]);
}

/// A client whose segment is resent after the server repeats its acknowledgment.
fn fast_retransmit_capture(base: u32, duplicates: usize) -> Vec<(TcpSpec, &'static [u8])> {
    let first = base.wrapping_add(1);
    let mut segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(base, 0, Tcp::SYN, 100), b""),
        (server(500, first, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(first, 501, Tcp::ACK, 100), b""),
        (client(first, 501, Tcp::ACK, 100), b"abc"),
    ];
    for _ in 0..duplicates {
        segments.push((server(501, first, Tcp::ACK, 100), b""));
    }
    segments.push((client(first, 501, Tcp::ACK, 100), b"abc"));
    segments
}

#[test]
fn resend_of_the_acknowledged_edge_after_duplicate_acks_is_fast() {
    assert_expert(
        &fast_retransmit_capture(100, 3),
        vec![
            finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                5,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #1)",
            ),
            finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                6,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #2)",
            ),
            finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                7,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #3)",
            ),
            finding(
                Severity::Warning,
                "tcp.fast_retransmission",
                8,
                "3 byte(s) at sequence 101 are resent after 3 duplicate acknowledgments of that sequence",
            ),
            not_closed(8),
        ],
        0,
        4,
        1,
    );
}

#[test]
fn fast_retransmission_is_reported_once_per_duplicate_streak() {
    let mut segments = fast_retransmit_capture(100, 3);
    segments.push((client(101, 501, Tcp::ACK, 100), b"abc"));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.duplicate_ack", 5),
            ("tcp.duplicate_ack", 6),
            ("tcp.duplicate_ack", 7),
            ("tcp.fast_retransmission", 8),
            ("tcp.retransmission", 9),
            ("tcp.not_closed_at_end", 9),
        ]
    );
}

#[test]
fn retransmission_without_enough_duplicate_acks_stays_plain() {
    let (findings, _) = analyze(&fast_retransmit_capture(100, 2));
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.duplicate_ack", 5),
            ("tcp.duplicate_ack", 6),
            ("tcp.retransmission", 7),
            ("tcp.not_closed_at_end", 7),
        ]
    );
}

#[test]
fn fast_retransmission_verdicts_survive_sequence_wraparound() {
    let (plain, _) = analyze(&fast_retransmit_capture(100, 3));
    let (wrapped, _) = analyze(&fast_retransmit_capture(u32::MAX - 2, 3));
    assert_eq!(codes_and_numbers(&wrapped), codes_and_numbers(&plain));
    assert!(wrapped.iter().any(|f| f.code == "tcp.fast_retransmission"));
}

fn out_of_order_capture(base: u32) -> Vec<(TcpSpec, &'static [u8])> {
    vec![
        (client(base, 501, Tcp::ACK, 100), b"ab"),
        (client(base.wrapping_add(4), 501, Tcp::ACK, 100), b"ef"),
        (client(base.wrapping_add(2), 501, Tcp::ACK, 100), b"cd"),
    ]
}

#[test]
fn segment_filling_a_reported_hole_is_out_of_order_not_a_retransmission() {
    assert_expert(
        &out_of_order_capture(1),
        vec![
            finding(
                Severity::Warning,
                "tcp.previous_segment_not_captured",
                2,
                "192.0.2.1:40000 resumes at sequence 5 before sequence 3 arrived",
            ),
            finding(
                Severity::Warning,
                "tcp.out_of_order",
                3,
                "192.0.2.1:40000 delivers the missing segment at sequence 3 after later data",
            ),
        ],
        0,
        2,
        0,
    );
}

#[test]
fn out_of_order_verdicts_survive_sequence_wraparound() {
    let (plain, _) = analyze(&out_of_order_capture(1));
    let (wrapped, _) = analyze(&out_of_order_capture(u32::MAX - 1));
    assert_eq!(codes_and_numbers(&wrapped), codes_and_numbers(&plain));
    assert_eq!(
        wrapped[1].message,
        "192.0.2.1:40000 delivers the missing segment at sequence 0 after later data"
    );
}

#[test]
fn partial_hole_fill_keeps_the_remaining_gap_open() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(1, 501, Tcp::ACK, 100), b"a"),
        (client(6, 501, Tcp::ACK, 100), b"f"),
        (client(2, 501, Tcp::ACK, 100), b"bc"),
        (client(4, 501, Tcp::ACK, 100), b"de"),
        (client(4, 501, Tcp::ACK, 100), b"de"),
    ];
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.previous_segment_not_captured", 2),
            ("tcp.out_of_order", 3),
            ("tcp.out_of_order", 4),
            ("tcp.retransmission", 5),
        ]
    );
}

#[test]
fn acknowledgment_beyond_captured_peer_data_is_unseen() {
    let mut segments = established();
    segments.push((server(501, 101, Tcp::ACK, 100), b"abc"));
    segments.push((client(101, 510, Tcp::ACK, 100), b""));
    assert_expert(
        &segments,
        vec![
            finding(
                Severity::Warning,
                "tcp.ack_unseen_segment",
                5,
                "192.0.2.1:40000 acknowledges sequence 510 but the capture holds the peer's data only up to 504",
            ),
            not_closed(5),
        ],
        0,
        1,
        1,
    );
}

#[test]
fn acknowledgment_without_captured_peer_data_is_unknown() {
    let one_direction: Vec<(TcpSpec, &[u8])> = vec![
        (client(101, 9_000, Tcp::ACK, 100), b"abc"),
        (client(104, 9_500, Tcp::ACK, 100), b""),
    ];
    assert_expert(&one_direction, Vec::new(), 0, 0, 0);

    let mid_stream: Vec<(TcpSpec, &[u8])> = vec![
        (server(500, 101, Tcp::SYN | Tcp::ACK, 100), b""),
        (client(101, 600, Tcp::ACK, 100), b""),
    ];
    assert_expert(&mid_stream, Vec::new(), 0, 0, 0);
}

#[test]
fn acknowledging_the_peer_fin_is_not_unseen() {
    let mut segments = established();
    segments.push((server(501, 101, Tcp::FIN | Tcp::ACK, 100), b"abc"));
    segments.push((client(101, 505, Tcp::ACK, 100), b""));
    let (findings, _) = analyze(&segments);
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn syn_renewal_discards_unseen_acknowledgment_context() {
    let mut segments = established();
    segments.push((server(501, 101, Tcp::ACK, 100), b"abc"));
    segments.push((client(900, 0, Tcp::SYN, 100), b""));
    segments.push((server(2_000, 901, Tcp::SYN | Tcp::ACK, 100), b""));
    segments.push((client(901, 9_000, Tcp::ACK, 100), b""));
    let (findings, _) = analyze(&segments);
    assert_eq!(codes_and_numbers(&findings), [("tcp.not_closed_at_end", 7)]);
}

#[test]
fn payload_after_the_senders_fin_and_repeated_fins_are_reported() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""));
    segments.push((client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""));
    segments.push((client(102, 501, Tcp::ACK, 100), b"xy"));
    assert_expert(
        &segments,
        vec![
            finding(
                Severity::Info,
                "tcp.fin_retransmission",
                5,
                "192.0.2.1:40000 resends its FIN at sequence 101",
            ),
            finding(
                Severity::Warning,
                "tcp.data_after_close",
                6,
                "192.0.2.1:40000 sent 2 byte(s) at sequence 102 after its FIN at sequence 101",
            ),
        ],
        0,
        1,
        1,
    );
}

#[test]
fn retransmitted_data_before_the_fin_is_not_data_after_close() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::FIN | Tcp::ACK, 100), b"abc"));
    segments.push((client(101, 501, Tcp::ACK, 100), b"abc"));
    let (findings, _) = analyze(&segments);
    assert_eq!(codes_and_numbers(&findings), [("tcp.retransmission", 5)]);
}

#[test]
fn syn_renewal_clears_the_fin_position() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::FIN | Tcp::ACK, 100), b""));
    segments.push((client(200, 0, Tcp::SYN, 100), b""));
    segments.push((server(900, 201, Tcp::SYN | Tcp::ACK, 100), b""));
    segments.push((client(201, 901, Tcp::ACK, 100), b"abc"));
    let (findings, _) = analyze(&segments);
    assert_eq!(codes_and_numbers(&findings), [("tcp.not_closed_at_end", 7)]);
}

#[test]
fn pure_ack_changing_the_window_is_an_update_not_a_duplicate() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::ACK, 100), b"abc"));
    segments.push((server(501, 101, Tcp::ACK, 100), b""));
    segments.push((server(501, 101, Tcp::ACK, 200), b""));
    segments.push((server(501, 101, Tcp::ACK, 200), b""));
    assert_expert(
        &segments,
        vec![
            finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                5,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #1)",
            ),
            finding(
                Severity::Info,
                "tcp.window_update",
                6,
                "198.51.100.2:443 changes its receive window to 200 without acknowledging new data",
            ),
            finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                7,
                "198.51.100.2:443 repeats acknowledgment 101 (duplicate #1)",
            ),
            not_closed(7),
        ],
        0,
        2,
        2,
    );
}

#[test]
fn window_changes_outside_pure_updates_are_not_window_updates() {
    let mut keep_alive = established();
    keep_alive.push((client(101, 501, Tcp::ACK, 100), b"a"));
    keep_alive.push((server(501, 102, Tcp::ACK, 100), b""));
    keep_alive.push((client(101, 501, Tcp::ACK, 300), b""));
    let (findings, _) = analyze(&keep_alive);
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.keep_alive", 6), ("tcp.not_closed_at_end", 6)]
    );

    let mut advancing = established();
    advancing.push((server(501, 101, Tcp::ACK, 100), b"abc"));
    advancing.push((client(101, 504, Tcp::ACK, 300), b""));
    let (findings, _) = analyze(&advancing);
    assert_eq!(codes_and_numbers(&findings), [("tcp.not_closed_at_end", 5)]);

    let mut after_handshake = established();
    after_handshake.push((server(501, 101, Tcp::ACK, 7_000), b""));
    let (findings, _) = analyze(&after_handshake);
    assert_eq!(codes_and_numbers(&findings), [("tcp.not_closed_at_end", 4)]);
}

#[test]
fn every_gap_that_is_watched_reports_its_own_fill() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(1, 501, Tcp::ACK, 100), b"a"),
        (client(5, 501, Tcp::ACK, 100), b"e"),
        (client(9, 501, Tcp::ACK, 100), b"i"),
        (client(2, 501, Tcp::ACK, 100), b"bcd"),
        (client(6, 501, Tcp::ACK, 100), b"fgh"),
    ];
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.previous_segment_not_captured", 2),
            ("tcp.previous_segment_not_captured", 3),
            ("tcp.out_of_order", 4),
            ("tcp.out_of_order", 5),
        ]
    );
}

#[test]
fn gaps_beyond_the_watched_limit_fill_silently() {
    let segments: Vec<(TcpSpec, &[u8])> = vec![
        (client(1, 501, Tcp::ACK, 100), b"a"),
        (client(5, 501, Tcp::ACK, 100), b"e"),
        (client(9, 501, Tcp::ACK, 100), b"i"),
        (client(13, 501, Tcp::ACK, 100), b"m"),
        (client(17, 501, Tcp::ACK, 100), b"q"),
        (client(21, 501, Tcp::ACK, 100), b"u"),
        (client(2, 501, Tcp::ACK, 100), b"bcd"),
        (client(18, 501, Tcp::ACK, 100), b"rst"),
    ];
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.previous_segment_not_captured", 2),
            ("tcp.previous_segment_not_captured", 3),
            ("tcp.previous_segment_not_captured", 4),
            ("tcp.previous_segment_not_captured", 5),
            ("tcp.previous_segment_not_captured", 6),
            ("tcp.out_of_order", 7),
            ("tcp.incomplete_at_end", 8),
        ]
    );
}

#[test]
fn conflicting_resend_after_duplicate_acks_is_never_fast() {
    let mut segments = fast_retransmit_capture(100, 3);
    segments.pop();
    segments.push((client(101, 501, Tcp::ACK, 100), b"xyz"));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.duplicate_ack", 5),
            ("tcp.duplicate_ack", 6),
            ("tcp.duplicate_ack", 7),
            ("tcp.retransmission_conflicting", 8),
            ("tcp.not_closed_at_end", 8),
        ]
    );
}

#[test]
fn resent_fin_carrying_undelivered_data_is_a_retransmission_only() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::ACK, 100), b"a"));
    segments.push((client(103, 501, Tcp::FIN | Tcp::ACK, 100), b"cd"));
    segments.push((client(103, 501, Tcp::FIN | Tcp::ACK, 100), b"cd"));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [
            ("tcp.previous_segment_not_captured", 5),
            ("tcp.retransmission", 6),
            ("tcp.incomplete_at_end", 6),
        ]
    );
}

#[test]
fn keep_alive_probe_is_not_an_unseen_acknowledgment() {
    let mut segments = established();
    segments.push((server(501, 101, Tcp::ACK, 100), b"abc"));
    segments.push((client(100, 900, Tcp::ACK, 100), b""));
    let (findings, _) = analyze(&segments);
    assert_eq!(
        codes_and_numbers(&findings),
        [("tcp.keep_alive", 5), ("tcp.not_closed_at_end", 5)]
    );
}

#[test]
fn reset_does_not_acknowledge_unseen_data() {
    let mut segments = established();
    segments.push((server(501, 101, Tcp::ACK, 100), b"abc"));
    segments.push((client(101, 900, Tcp::RST | Tcp::ACK, 0), b""));
    let (findings, _) = analyze(&segments);
    assert_eq!(codes_and_numbers(&findings), [("tcp.reset", 5)]);
}

#[test]
fn window_closing_to_zero_is_not_a_window_update() {
    let mut segments = established();
    segments.push((client(101, 501, Tcp::ACK, 100), b"abc"));
    segments.push((server(501, 101, Tcp::ACK, 100), b""));
    segments.push((server(501, 101, Tcp::ACK, 0), b""));
    let (findings, _) = analyze(&segments);
    assert!(
        findings
            .iter()
            .all(|finding| finding.code != "tcp.window_update"),
        "unexpected window update: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.zero_window")
    );
}
