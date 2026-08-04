// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::{Duration, UNIX_EPOCH};

use super::super::{
    AnalysisOptions, Tcp, build_bytes, capture, expert, registry, run, tcp_flags_packet,
    tcp_syn_packet,
};
use bytes::Bytes;
use packetcraftr_capture::{Frame, LinkType, Reader, Writer};
use packetcraftr_packet::layer::Raw;

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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
    let (trailing, _) = collector.finish(&pipeline.trailing_tcp_events, pipeline.frames_read);
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
