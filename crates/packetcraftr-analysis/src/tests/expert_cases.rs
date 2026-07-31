// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn expert_detects_retransmission_duplicate_ack_zero_window_keep_alive_and_reset() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut collector = expert::ExpertCollector::new();
    let mut findings = Vec::new();
    let pipeline = run(
        &mut capture(vec![
            // 1: data seq 100..104 from A.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: exact retransmission of frame 1.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 3: B still acknowledges only 100, so A's data is outstanding.
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 512, b""),
            // 4-5: B repeats the acknowledgment twice: duplicates #1 and #2.
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 512, b""),
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 512, b""),
            // 6: A advertises a zero window.
            tcp_flags_packet(A, 1000, B, 2000, 104, 900, Tcp::ACK, 0, b""),
            // 7: keep-alive probe from A: one byte before its own next
            // sequence.
            tcp_flags_packet(A, 1000, B, 2000, 103, 900, Tcp::ACK, 512, b"k"),
            // 8: B resets the conversation.
            tcp_flags_packet(B, 2000, A, 1000, 501, 0, Tcp::RST, 0, b""),
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
    let (trailing, summary) = collector.finish(&pipeline);
    findings.extend(trailing);

    let by_code = |code: &str| {
        findings
            .iter()
            .filter(|finding| finding.code == code)
            .map(|finding| finding.number)
            .collect::<Vec<_>>()
    };
    assert_eq!(by_code("tcp.retransmission"), [2]);
    assert_eq!(by_code("tcp.duplicate_ack"), [4, 5]);
    assert_eq!(by_code("tcp.zero_window"), [6]);
    assert_eq!(by_code("tcp.keep_alive"), [7]);
    assert_eq!(by_code("tcp.reset"), [8]);
    // Nothing was left buffered, and every per-frame finding names the
    // conversation the filter language can select.
    assert_eq!(by_code("tcp.incomplete_at_end"), [] as [u64; 0]);
    assert!(findings.iter().all(|finding| finding.stream
        == Some(expert::StreamRef {
            transport: expert::StreamTransport::Tcp,
            index: 0,
        })));
    assert_eq!(summary.findings, findings.len() as u64);
    assert_eq!(summary.codes["tcp.duplicate_ack"], 2);
    assert!(summary.warnings >= 4);
    assert_eq!(summary.notes, 1);
    // The keep-alive probe's one garbage byte below the cursor is not a
    // conflicting retransmission, so nothing here is an error.
    assert_eq!(summary.errors, 0, "{findings:?}");
}

#[test]
fn expert_reports_out_of_order_data_and_window_full() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1-2: unscaled handshake; B advertises a 4-byte window.
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, None),
            // 3: A sends 4 bytes, exactly filling B's window.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"full"),
            // 4: A skips ahead: sequence 112 before 104..112 ever arrived.
            tcp_flags_packet(A, 1000, B, 2000, 112, 500, Tcp::ACK, 512, b"late"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full" && finding.number == 3),
        "{findings:?}"
    );
    assert!(
        findings.iter().any(
            |finding| finding.code == "tcp.previous_segment_not_captured" && finding.number == 4
        ),
        "{findings:?}"
    );
    // The skipped-ahead bytes stayed buffered behind the hole to the end,
    // and the finding still names the conversation they belong to.
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.incomplete_at_end"
                && finding.number == 4
                && finding.stream
                    == Some(expert::StreamRef {
                        transport: expert::StreamTransport::Tcp,
                        index: 0,
                    })),
        "{findings:?}"
    );
}

#[test]
fn expert_applies_the_negotiated_window_scale_and_requires_both_syns() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1-2: both SYNs offer window scaling. The SYN-ACK's own window
            // field is never scaled, so B's raw 4 means 4 for now.
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, Some(1)),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, Some(2)),
            // 3: B's first post-handshake window is scaled: 8 << 2 = 32.
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 8, b""),
            // 4: 4 bytes would fill the raw window but not the scaled one.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"full"),
            // 5: 28 more bytes reach the scaled 32-byte limit.
            tcp_flags_packet(
                A,
                1000,
                B,
                2000,
                104,
                500,
                Tcp::ACK,
                512,
                b"abcdefghijklmnopqrstuvwxyz01",
            ),
            // 6-7: a second conversation with no captured handshake never
            // reports window fullness — its scale is unknowable.
            tcp_flags_packet(B, 4000, A, 3000, 900, 200, Tcp::ACK, 4, b""),
            tcp_flags_packet(A, 3000, B, 4000, 200, 900, Tcp::ACK, 512, b"data"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    let window_full = findings
        .iter()
        .filter(|finding| finding.code == "tcp.window_full")
        .collect::<Vec<_>>();
    assert_eq!(window_full.len(), 1, "{findings:?}");
    assert_eq!(window_full[0].number, 5);
    assert!(
        window_full[0].message.contains("32-byte receive window"),
        "{}",
        window_full[0].message
    );
}

#[test]
fn expert_counts_a_fin_toward_window_fullness() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1-2: unscaled handshake; B advertises a 5-byte window.
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 5, None),
            // 3: four data bytes plus the FIN's sequence number fill it.
            tcp_flags_packet(
                A,
                1000,
                B,
                2000,
                100,
                500,
                Tcp::ACK | Tcp::FIN,
                512,
                b"data",
            ),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full" && finding.number == 3),
        "{findings:?}"
    );
}

#[test]
fn data_past_the_advertised_edge_is_an_overrun_not_a_full_window() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, None),
            // 3: six bytes against a four-byte window go two bytes past the
            // edge the receiver permitted.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"toobig"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full"),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.window_exceeded"
                && finding.number == 3
                && finding.message.contains("2 byte(s) beyond")),
        "{findings:?}"
    );
}

#[test]
fn expert_reads_a_syn_carried_window_unscaled() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1-2: both SYNs offer scaling, but B's window of 4 rides on the
            // SYN-ACK itself, where RFC 7323 forbids scaling.
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, Some(1)),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, Some(2)),
            // 3: 4 bytes fill that unscaled window exactly.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"full"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full"
                && finding.number == 3
                && finding.message.contains("4-byte receive window")),
        "{findings:?}"
    );
}

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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, summary) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
    let (trailing, _) = collector.finish(&pipeline);
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
fn a_gap_beyond_the_reassembly_window_re_anchors_instead_of_aborting() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Sparse and filtered captures routinely jump further than the bounded
    // per-flow reassembly window; the run must survive and still report the
    // missing range from the header view.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 2_000_104, 0, Tcp::ACK, 512, b"far!"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings.iter().any(
            |finding| finding.code == "tcp.previous_segment_not_captured" && finding.number == 2
        ),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn idle_eviction_re_anchors_the_expert_observation_base() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    // The flow idles out between frames 1 and 2, so the reassembler
    // re-anchors at sequence 5000; bytes 4996..5000 in frame 3 were never
    // captured and must not be reported as previously seen.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (seconds, packet) in [
        (
            0,
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
        ),
        (
            600,
            tcp_flags_packet(A, 1000, B, 2000, 5000, 0, Tcp::ACK, 512, b"data"),
        ),
        (
            601,
            tcp_flags_packet(A, 1000, B, 2000, 4996, 0, Tcp::ACK, 512, b"prio"),
        ),
    ] {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    build_bytes(packet),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut reader,
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn a_reset_retires_both_directions_and_their_buffered_residue() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // B's out-of-order bytes were still buffered when A reset the
    // connection; the reset ended the conversation, so the capture ending
    // later reveals nothing incomplete.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 508, 104, Tcp::ACK, 512, b"late"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::RST, 0, b""),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.reset" && finding.number == 4),
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
fn a_syn_ack_reusing_its_sequence_for_a_new_client_starts_fresh() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 3's SYN-ACK repeats B's old sequence base, but it acknowledges
    // a client SYN this capture never saw — proof of reuse even though the
    // base coincides. Frame 4 belongs to the new client and must not be
    // measured against the old generation.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(900_000_001), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 900_000_001, 500, Tcp::ACK, 512, b"data"),
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
    let (trailing, _) = collector.finish(&pipeline);
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
fn a_retransmitted_fast_open_syn_is_a_retransmission_not_reuse() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // A Fast Open SYN carries payload from the start, so its retransmission
    // must keep the tracked generation and be reported as the repeat it is.
    let mut fast_open = tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None);
    fast_open.push(Raw::new(Bytes::from_static(b"tfo!")));
    let pipeline = run(
        &mut capture(vec![fast_open.clone(), fast_open]),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.code == "tcp.retransmission")
            .map(|finding| finding.number)
            .collect::<Vec<_>>(),
        [2],
        "{findings:?}"
    );
}

#[test]
fn a_pure_syn_reusing_the_same_isn_after_data_starts_fresh() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // A handshake SYN only retransmits while half-open; data already flowed
    // here, so frame 2 opens a new connection even though its implied base
    // lands on the old one, and frame 3's fresh bytes are not a conflicting
    // retransmission of the old generation's.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"newz"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn a_retransmitted_syn_keeps_the_peers_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 4 repeats A's opening SYN — as when the SYN-ACK was lost — and
    // must not discard what is known about B, or B's retransmission in
    // frame 5 loses its observation base and goes unreported.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 512, b"data"),
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 512, b"data"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.code == "tcp.retransmission")
            .map(|finding| finding.number)
            .collect::<Vec<_>>(),
        [5],
        "{findings:?}"
    );
}

#[test]
fn a_duplicate_teardown_acknowledgment_is_not_loss_evidence() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // A's payload is fully acknowledged; only the FIN's sequence number is
    // not. Repeating that acknowledgment repeats no data in flight.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::ACK | Tcp::FIN, 512, b""),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b""),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b""),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.duplicate_ack"),
        "{findings:?}"
    );
}

#[test]
fn closed_flow_retransmissions_stop_at_the_payload_boundary() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The FIN consumed sequence 104, but no payload ever existed there; a
    // post-close segment crossing that position is not wholly previously
    // seen data and must not be reported as such.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 102, 0, Tcp::ACK, 512, b"tax"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn expert_does_not_call_a_gap_filling_segment_a_retransmission() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 3's bytes arrive for the first time and complete the close in
    // the same frame; a close this frame produced says nothing about the
    // frame's own bytes.
    let pipeline = run(
        &mut capture(vec![
            // 1: data 100..104 delivered.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: an out-of-order FIN at 108 waits behind the 104..108 hole.
            tcp_flags_packet(A, 1000, B, 2000, 108, 0, Tcp::ACK | Tcp::FIN, 512, b""),
            // 3: 104..108 arrives for the first time, closing the flow.
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::ACK, 512, b"gap!"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn a_one_byte_segment_without_ack_is_not_a_keep_alive() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Keep-alives exist only in synchronized state, so the ACK-less one-byte
    // overlap in frame 2 is a conflicting retransmission, not a probe.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 103, 0, 0, 512, b"g"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.keep_alive"),
        "{findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.retransmission_conflicting" && finding.number == 2),
        "{findings:?}"
    );
}

#[test]
fn a_syn_reusing_a_closed_generations_sequence_starts_fresh() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The close ended the old generation; a SYN whose implied base lands on
    // the same sequence is a new connection, and its data in the old range
    // is not a retransmission.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"newx"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn a_zero_length_keep_alive_is_not_a_duplicate_acknowledgment() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            // 1: A sends 8 bytes; B will acknowledge only half of them, so
            // data stays outstanding and a duplicate ACK would be eligible.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"datadata"),
            // 2: B replies with data, acknowledging 104.
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"resp"),
            // 3: B's zero-length keep-alive necessarily repeats that
            // acknowledgment; it is a probe, not loss evidence.
            tcp_flags_packet(B, 2000, A, 1000, 503, 104, Tcp::ACK, 512, b""),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.keep_alive" && finding.number == 3),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.duplicate_ack"),
        "{findings:?}"
    );
}

#[test]
fn a_simultaneous_open_syn_ack_still_records_window_facts() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // B's SYN-ACK repeats its own SYN's base — a renewal — but it carries
    // the direction's first acknowledgment and window, which window
    // tracking needs.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"full"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full" && finding.number == 4),
        "{findings:?}"
    );
}

#[test]
fn a_stale_reordered_acknowledgment_does_not_roll_window_state_back() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 5 is an older acknowledgment arriving late; taking it as the
    // baseline would make frame 6 look like it overran a 4-byte window.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"datadata"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 108, Tcp::ACK, 512, b""),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 4, b""),
            tcp_flags_packet(A, 1000, B, 2000, 108, 500, Tcp::ACK, 512, b"more"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full"
                || finding.code == "tcp.window_exceeded"),
        "{findings:?}"
    );
}

#[test]
fn a_syn_ack_confirming_the_new_client_keeps_its_reverse_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    // Frame 1 is a stale server SYN-ACK from an earlier connection; frame 3
    // replaces that generation, but it acknowledges the new client SYN of
    // frame 2, which therefore must not be evicted with it.
    let (observed, _) = observe(
        &mut capture(vec![
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_syn_packet(A, 1000, B, 2000, 9099, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 6000, Some(9100), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 9100, 6001, Tcp::ACK, 512, b"data"),
        ]),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
    );
    // The stale server state is evicted by the new client SYN itself in
    // frame 2; the confirming SYN-ACK in frame 3 evicts nothing further,
    // and the new client's data still delivers through its preserved flow.
    assert_eq!(
        observed
            .iter()
            .map(|record| record.tcp_event_count)
            .collect::<Vec<_>>(),
        [0, 1, 0, 1],
        "{observed:?}"
    );
}

#[test]
fn a_retransmitted_older_segment_never_replaces_the_window() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 6 retransmits an older segment with a newer acknowledgment and a
    // small window; TCP's SND.WL1 rule keeps the newer advertisement, so
    // frame 7 fits comfortably.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"datadata"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 512, b"resp"),
            tcp_flags_packet(B, 2000, A, 1000, 504, 108, Tcp::ACK, 512, b"more"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 108, Tcp::ACK, 4, b"resp"),
            tcp_flags_packet(A, 1000, B, 2000, 108, 508, Tcp::ACK, 512, b"tail"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full"
                || finding.code == "tcp.window_exceeded"),
        "{findings:?}"
    );
}

#[test]
fn data_against_a_zero_window_is_a_probe_or_an_overrun() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            // 3: B closes its window entirely.
            tcp_flags_packet(B, 2000, A, 1000, 500, 100, Tcp::ACK, 0, b""),
            // 4: one new byte is the conventional zero-window probe.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::ACK, 512, b"x"),
            // 5: four more bytes overrun the closed window outright.
            tcp_flags_packet(A, 1000, B, 2000, 101, 500, Tcp::ACK, 512, b"more"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    let by_code = |code: &str| {
        findings
            .iter()
            .filter(|finding| finding.code == code)
            .map(|finding| finding.number)
            .collect::<Vec<_>>()
    };
    assert_eq!(by_code("tcp.zero_window"), [3], "{findings:?}");
    assert_eq!(by_code("tcp.zero_window_probe"), [4], "{findings:?}");
    assert_eq!(by_code("tcp.window_exceeded"), [5], "{findings:?}");
}

#[test]
fn zero_window_findings_need_no_handshake_and_probes_sit_at_the_edge() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // No SYN was captured, but zero is unaffected by window scaling: the
    // edge probe is informational and the far jump is an overrun.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 0, b""),
            // 3: one byte at the acknowledged edge probes the closed window.
            tcp_flags_packet(A, 1000, B, 2000, 104, 500, Tcp::ACK, 512, b"x"),
            // 4: one byte far past the edge is no probe.
            tcp_flags_packet(A, 1000, B, 2000, 205, 500, Tcp::ACK, 512, b"y"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    let by_code = |code: &str| {
        findings
            .iter()
            .filter(|finding| finding.code == code)
            .map(|finding| finding.number)
            .collect::<Vec<_>>()
    };
    assert_eq!(by_code("tcp.zero_window"), [2], "{findings:?}");
    assert_eq!(by_code("tcp.zero_window_probe"), [3], "{findings:?}");
    assert_eq!(by_code("tcp.window_exceeded"), [4], "{findings:?}");
}

#[test]
fn a_stale_syn_ack_does_not_survive_a_new_client_syn() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // Frame 1 is a stale SYN-ACK; frame 2's fresh client SYN replaces the
    // conversation, so frame 3's data must re-anchor rather than buffer
    // behind a gap fabricated from the old base.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_syn_packet(A, 1000, B, 2000, 8099, None, 512, None),
            tcp_flags_packet(B, 2000, A, 1000, 700, 8100, Tcp::ACK, 512, b"data"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.incomplete_at_end"),
        "{findings:?}"
    );
}

#[test]
fn repeated_persist_probes_stay_zero_window_probes() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // The second identical probe sits one before the advanced cursor — the
    // keep-alive shape — but the peer's window is still closed, so it is
    // the persist timer at work, not a keep-alive.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 104, Tcp::ACK, 0, b""),
            tcp_flags_packet(A, 1000, B, 2000, 104, 500, Tcp::ACK, 512, b"x"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 500, Tcp::ACK, 512, b"x"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    let by_code = |code: &str| {
        findings
            .iter()
            .filter(|finding| finding.code == code)
            .map(|finding| finding.number)
            .collect::<Vec<_>>()
    };
    assert_eq!(by_code("tcp.zero_window_probe"), [3, 4], "{findings:?}");
    assert_eq!(by_code("tcp.keep_alive"), [] as [u64; 0], "{findings:?}");
}

#[test]
fn a_reset_payload_is_not_stream_data_for_window_analysis() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 4, None),
            // 3: the reset's diagnostic payload is not governed by B's
            // 4-byte receive window.
            tcp_flags_packet(A, 1000, B, 2000, 100, 500, Tcp::RST, 0, b"denied"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.reset" && finding.number == 3),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.window_full"
                || finding.code == "tcp.window_exceeded"),
        "{findings:?}"
    );
}

#[test]
fn a_reset_payload_overlapping_delivered_bytes_is_not_a_retransmission() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 2: the reset's explanatory text overlaps the delivered range
            // with different bytes; it is a reset, not a conflicting
            // retransmission.
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::RST, 0, b"gone"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.reset" && finding.number == 2),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code.starts_with("tcp.retransmission")),
        "{findings:?}"
    );
}

#[test]
fn a_closed_direction_reports_no_keep_alives() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut findings = Vec::new();
    let mut collector = expert::ExpertCollector::new();
    // A sender cannot probe after its FIN; the post-close byte at the FIN's
    // sequence is a leftover, not a keep-alive.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::ACK, 512, b"g"),
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
    let (trailing, _) = collector.finish(&pipeline);
    findings.extend(trailing);

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "tcp.keep_alive"),
        "{findings:?}"
    );
}

#[test]
fn a_simultaneous_open_keeps_both_directions_of_reassembly_state() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    // Two pure SYNs of one handshake are not tuple reuse: neither may evict
    // the other's just-created flow, so no eviction evidence appears.
    let (observed, _) = observe(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, None, 512, None),
        ]),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
    );
    assert!(
        observed.iter().all(|record| record.tcp_event_count == 0),
        "{observed:?}"
    );
}
