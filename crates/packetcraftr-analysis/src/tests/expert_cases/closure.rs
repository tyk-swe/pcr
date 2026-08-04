// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{
    AnalysisOptions, Tcp, capture, expert, observe, registry, run, tcp_flags_packet, tcp_syn_packet,
};

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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
