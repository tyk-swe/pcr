// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::{
    analysis::{self, stats},
    filter::Filter,
    frame::Frame,
    protocol::transport::Tcp,
};

use crate::common;

fn collect(frames: &[Frame], table: stats::Table, filter: Option<&Filter>) -> stats::Report {
    let mut collector = stats::Collector::for_table(Duration::from_secs(1), table).unwrap();
    let summary = analysis::run(
        &mut common::reader(frames),
        common::registry(),
        &analysis::Options {
            filter,
            ..Default::default()
        },
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .unwrap();
    collector.finish(&summary)
}

#[test]
fn overview_matches_individual_tables_without_collecting_ports_or_io() {
    let registry = common::registry();
    let frames = [
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_000,
            9,
            b"hello",
        ),
        common::udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(2),
            common::SERVER,
            common::CLIENT,
            9,
            40_000,
            b"reply",
        ),
        common::tcp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(1),
            common::client_tcp(1, 0, 2, 1024),
            b"",
        ),
    ];
    let overview = collect(&frames, stats::Table::Overview, None);
    assert_eq!(overview.frames, 3);
    assert_eq!(
        overview.bytes,
        frames
            .iter()
            .map(|frame| u64::from(frame.captured_length()))
            .sum::<u64>()
    );
    assert_eq!(
        overview.protocols,
        collect(&frames, stats::Table::Protocols, None).protocols
    );
    assert_eq!(
        overview.endpoints,
        collect(&frames, stats::Table::Endpoints, None).endpoints
    );
    assert_eq!(
        overview.conversations,
        collect(&frames, stats::Table::Conversations, None).conversations
    );
    assert_eq!(overview.protocol_count, overview.protocols.len());
    assert_eq!(overview.endpoint_count, 2);
    assert_eq!(overview.conversation_count, 2);
    assert!(overview.ports.is_empty());
    assert!(overview.io.is_empty());
    assert_eq!(overview.io_origin, None);
    assert_eq!(overview.duration(), Some(Duration::from_secs(2)));
    assert_eq!(overview.packet_rate(), Some(1.5));
}

#[test]
fn overview_respects_filters_and_handles_empty_and_zero_duration() {
    let registry = common::registry();
    let frames = [
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_000,
            9,
            b"hello",
        ),
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_001,
            9,
            b"reply",
        ),
    ];
    let filter = Filter::compile("udp.srcport == 40001", &registry, Default::default()).unwrap();
    let report = collect(&frames, stats::Table::Overview, Some(&filter));
    assert_eq!(report.frames, 1);
    assert_eq!(report.conversation_count, 1);
    assert_eq!(report.conversations[0].stream, 1, "index is capture-global");
    assert_eq!(report.duration(), Some(Duration::ZERO));
    assert_eq!(report.packet_rate(), None);
    assert_eq!(report.byte_rate(), None);
    assert!(report.average_packet_size().is_some());
    for empty in [
        collect(&[], stats::Table::Overview, None),
        collect(&frames[..1], stats::Table::Overview, Some(&filter)),
    ] {
        assert_eq!((empty.frames, empty.bytes), (0, 0));
        assert_eq!(
            (
                empty.protocol_count,
                empty.endpoint_count,
                empty.conversation_count
            ),
            (0, 0, 0)
        );
        assert_eq!(empty.duration(), None);
        assert_eq!(empty.average_packet_size(), None);
    }
}

/// A complete three-way handshake, one data exchange, and the closing ACKs.
fn rtt_capture() -> Vec<Frame> {
    let registry = common::registry();
    let at = |seconds: u64| UNIX_EPOCH + Duration::from_secs(seconds);
    let frames = vec![
        // Handshake: SYN at 1s, SYN-ACK at 2s, ACK at 3s.
        common::tcp_frame(
            &registry,
            at(1),
            common::client_tcp(1, 0, Tcp::SYN, 1024),
            b"",
        ),
        common::tcp_frame(
            &registry,
            at(2),
            common::server_tcp(1, 2, Tcp::SYN | Tcp::ACK, 1024),
            b"",
        ),
        common::tcp_frame(
            &registry,
            at(3),
            common::client_tcp(2, 2, Tcp::ACK, 1024),
            b"",
        ),
        // First exchange: 4 bytes at 4s, acknowledged at 5s.
        common::tcp_frame(
            &registry,
            at(4),
            common::client_tcp(2, 2, Tcp::ACK, 1024),
            b"abcd",
        ),
        common::tcp_frame(
            &registry,
            at(5),
            common::server_tcp(2, 6, Tcp::ACK, 1024),
            b"",
        ),
        // Second exchange: 2 bytes at 6s, acknowledged at 8s.
        common::tcp_frame(
            &registry,
            at(6),
            common::client_tcp(6, 2, Tcp::ACK, 1024),
            b"ef",
        ),
        common::tcp_frame(
            &registry,
            at(8),
            common::server_tcp(2, 8, Tcp::ACK, 1024),
            b"",
        ),
    ];
    frames
}

#[test]
fn rtt_rows_pair_the_handshake_with_first_data_round_trips() {
    let report = collect(&rtt_capture(), stats::Table::Rtt, None);
    assert_eq!(report.rtt.len(), 1);
    let row = &report.rtt[0];
    assert_eq!(
        row.transport,
        packetcraftr_core::analysis::StreamTransport::Tcp
    );
    assert_eq!(row.stream, 0);
    assert_eq!(
        (row.address_a.to_string(), row.port_a),
        ("192.0.2.1".to_owned(), 40_000)
    );
    assert_eq!(row.handshake_rtt_ns, Some(1_000_000_000));
    assert_eq!(row.samples, 2);
    assert_eq!(row.min_rtt_ns, Some(1_000_000_000));
    assert_eq!(row.mean_rtt_ns, Some(1_500_000_000));
    assert_eq!(row.max_rtt_ns, Some(2_000_000_000));
}

#[test]
fn rtt_rows_lack_evidence_when_the_capture_starts_midstream() {
    let registry = common::registry();
    let at = |seconds: u64| UNIX_EPOCH + Duration::from_secs(seconds);
    let frames = [
        common::tcp_frame(
            &registry,
            at(1),
            common::client_tcp(100, 200, Tcp::ACK, 1024),
            b"payload",
        ),
        common::tcp_frame(
            &registry,
            at(2),
            common::server_tcp(200, 107, Tcp::ACK, 1024),
            b"",
        ),
    ];
    let report = collect(&frames, stats::Table::Rtt, None);
    assert_eq!(report.rtt.len(), 1);
    let row = &report.rtt[0];
    assert_eq!(row.handshake_rtt_ns, None, "no SYN was captured");
    assert_eq!(row.samples, 1, "the single data segment was acknowledged");
    assert_eq!(row.min_rtt_ns, row.mean_rtt_ns);
    assert_eq!(row.max_rtt_ns, Some(1_000_000_000));
}

#[test]
fn rtt_skips_samples_across_clock_regressions() {
    let mut frames = rtt_capture();
    // Pull the first exchange's ACK before its data segment: the regressed
    // clock yields no sample for it, while the later exchange still measures.
    frames[4] = common::tcp_frame(
        &common::registry(),
        UNIX_EPOCH + Duration::from_secs(3),
        common::server_tcp(2, 6, Tcp::ACK, 1024),
        b"",
    );
    let report = collect(&frames, stats::Table::Rtt, None);
    assert_eq!(report.rtt[0].samples, 1);
    assert_eq!(report.rtt[0].min_rtt_ns, Some(2_000_000_000));
    assert_eq!(report.clock.regressions, 1);
}

#[test]
fn rtt_tracks_wrapping_sequences_and_piggybacked_acks() {
    let registry = common::registry();
    let at = |seconds: u64| UNIX_EPOCH + Duration::from_secs(seconds);
    // The sequence ends exactly at the wraparound; the covering ACK arrives
    // piggybacked on the peer's own data segment.
    let sequence = u32::MAX - 3;
    let frames = [
        common::tcp_frame(
            &registry,
            at(1),
            common::client_tcp(sequence, 0, Tcp::ACK, 1024),
            b"1234",
        ),
        common::tcp_frame(
            &registry,
            at(2),
            common::server_tcp(500, 3, Tcp::ACK, 1024),
            b"resp",
        ),
    ];
    let report = collect(&frames, stats::Table::Rtt, None);
    assert_eq!(report.rtt.len(), 1);
    // Only the client's wrapped segment is acknowledged within the capture.
    assert_eq!(report.rtt[0].samples, 1);
    assert_eq!(report.rtt[0].min_rtt_ns, Some(1_000_000_000));
}

#[test]
fn rtt_outstanding_window_evicts_without_inventing_samples() {
    let registry = common::registry();
    let at = |seconds: u64| UNIX_EPOCH + Duration::from_secs(seconds);
    let mut frames = Vec::new();
    let mut sequence = 100_u32;
    for index in 0..(stats::MAX_OUTSTANDING_SEGMENTS + 2) {
        // Every segment lands in the same second, so eviction is what decides
        // which send time the one covering ACK can still reach.
        frames.push(common::tcp_frame(
            &registry,
            at(1),
            common::client_tcp(sequence, 0, Tcp::ACK, 1024),
            b"ab",
        ));
        sequence = sequence.wrapping_add(2);
        let _ = index;
    }
    // One final ACK covers every outstanding byte.
    frames.push(common::tcp_frame(
        &registry,
        at(2),
        common::server_tcp(0, sequence, Tcp::ACK, 1024),
        b"",
    ));
    let report = collect(&frames, stats::Table::Rtt, None);
    let row = &report.rtt[0];
    assert_eq!(row.samples, 1);
    // The first two segments left the window; the sample measures the third.
    assert_eq!(row.min_rtt_ns, Some(1_000_000_000));
}
