// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{
    AnalysisOptions, Tcp, capture, expert, registry, run, tcp_flags_packet, tcp_syn_packet,
};

#[test]
fn expert_starts_fresh_header_state_when_a_connection_is_reused() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1: the first connection sends 100..104.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: the four-tuple is reused: a new SYN with an unrelated ISN
            // that happens to sit just before the old next sequence.
            tcp_syn_packet(A, 1000, B, 2000, 102, None, 512, None),
            // 3: the new connection's first byte. Against the old cursor of
            // 104 this looked like a keep-alive probe.
            tcp_flags_packet(A, 1000, B, 2000, 103, 0, Tcp::ACK, 512, b"x"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    let codes = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<Vec<_>>();
    assert!(!codes.contains(&"tcp.keep_alive"), "{findings:?}");
    assert!(
        !codes.contains(&"tcp.previous_segment_not_captured"),
        "{findings:?}"
    );
    assert!(!codes.contains(&"tcp.retransmission"), "{findings:?}");
}

#[test]
fn expert_ignores_retransmissions_of_data_the_capture_never_observed() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1: the capture starts mid-stream at sequence 100.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: 96..100 predates the capture base entirely; the reassembler
            // treats it as old data, but nothing here was ever observed.
            tcp_flags_packet(A, 1000, B, 2000, 96, 0, Tcp::ACK, 512, b"prio"),
            // 3: 98..104 straddles the base: only 100..104 was seen before.
            tcp_flags_packet(A, 1000, B, 2000, 98, 0, Tcp::ACK, 512, b"xxdata"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    let retransmissions = findings
        .iter()
        .filter(|finding| finding.code == "tcp.retransmission")
        .collect::<Vec<_>>();
    assert_eq!(retransmissions.len(), 1, "{findings:?}");
    assert_eq!(retransmissions[0].number, 3);
    assert!(
        retransmissions[0]
            .message
            .contains("4 byte(s) within the segment at sequence 98"),
        "{}",
        retransmissions[0].message
    );
}

#[test]
fn a_reused_tuple_replaces_reverse_reassembly_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Without eviction on reuse, frame 4 would be measured against B's old
    // base of 500 — a forward gap of hundreds of megabytes — and the run
    // would fail on the per-flow byte limit instead of starting fresh.
    let pipeline = run(
        &mut capture(vec![
            // 1-2: the first connection exchanges data in both directions.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"data"),
            // 3: the four-tuple is reused by a new client SYN.
            tcp_syn_packet(A, 1000, B, 2000, 5000, None, 512, None),
            // 4: the server's reply belongs to the new generation and sits
            // nowhere near the old reverse base.
            tcp_flags_packet(B, 2000, A, 1000, 900_000_000, 5001, Tcp::ACK, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.incomplete_at_end"),
        "{findings:?}"
    );
}

#[test]
fn expert_reports_a_gap_carried_by_a_bare_fin() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1: data 100..104.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: a payloadless FIN at 112 skips over 104..112.
            tcp_flags_packet(A, 1000, B, 2000, 112, 0, Tcp::ACK | Tcp::FIN, 512, b""),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        findings.iter().any(
            |finding| finding.code == "tcp.previous_segment_not_captured" && finding.number == 2
        ),
        "{findings:?}"
    );
}

#[test]
fn expert_reports_retransmissions_arriving_after_a_clean_close() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The reassembler forgets a cleanly closed flow, so the repeated
    // data-bearing FIN produces no event there; the close itself proved the
    // bytes were delivered, which is what lets the header view report it.
    let pipeline = run(
        &mut capture(vec![
            // 1: data and FIN delivered contiguously: the flow closes.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
            // 2: the closing segment is retransmitted, as when its final
            // acknowledgment was lost.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    let retransmissions = findings
        .iter()
        .filter(|finding| finding.code == "tcp.retransmission")
        .collect::<Vec<_>>();
    assert_eq!(retransmissions.len(), 1, "{findings:?}");
    assert_eq!(retransmissions[0].number, 2);
    assert!(
        retransmissions[0]
            .message
            .contains("4 byte(s) at sequence 100"),
        "{}",
        retransmissions[0].message
    );
}

#[test]
fn expert_reports_keep_alive_probes_without_retransmission_findings() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The probe's garbage byte overlaps the delivered stream, so the
    // reassembler reports a conflicting overlap; expert must recognise the
    // keep-alive shape and report only the probe.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 103, 0, Tcp::ACK, 512, b"g"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, summary) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.keep_alive" && finding.number == 2),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
    assert_eq!(summary.errors, 0);
}

#[test]
fn a_reuse_first_seen_through_a_syn_ack_also_replaces_reverse_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The new connection's opening SYN was not captured, so the reuse is
    // first visible as a SYN-ACK; the old reverse state must still go, or
    // frame 4 would be measured against the old base and abort the run.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(B, 2000, A, 1000, 6000, Some(900_000_001), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 900_000_001, 6001, Tcp::ACK, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
    // The SYN-ACK also retires the reverse header state, so the new
    // client's first segment is not measured against the old cursor.
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.previous_segment_not_captured"),
        "{findings:?}"
    );
}

#[test]
fn a_one_sided_reuse_first_seen_as_a_new_syn_replaces_reverse_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The old capture holds only B's direction, so the new client SYN has
    // no forward state to compare against; the reverse still carried
    // payload, which is what proves it belongs to an earlier connection.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(A, 1000, B, 2000, 5000, None, 512, None),
            tcp_flags_packet(B, 2000, A, 1000, 900_000_000, 5001, Tcp::ACK, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.previous_segment_not_captured"),
        "{findings:?}"
    );
}

#[test]
fn a_one_sided_reuse_first_seen_as_a_syn_ack_replaces_reverse_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The old capture holds only A's direction, and the reuse is first
    // visible as B's SYN-ACK; the acknowledgment names the new client SYN,
    // which the old reverse base cannot match.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(B, 2000, A, 1000, 6000, Some(900_000_001), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 900_000_001, 6001, Tcp::ACK, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.previous_segment_not_captured"),
        "{findings:?}"
    );
}
