// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{
    AnalysisOptions, Tcp, capture, expert, observe, registry, run, tcp_flags_packet, tcp_syn_packet,
};

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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
