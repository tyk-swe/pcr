// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{
    AnalysisOptions, Tcp, capture, expert, registry, run, tcp_flags_packet, tcp_syn_packet,
};

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
    let (trailing, summary) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
