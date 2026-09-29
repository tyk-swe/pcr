// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{
    reader, registry,
    tls_capture::{Capture, Stream},
};
use packetcraftr_core::{
    analysis::{self, stats},
    error::BoundaryError,
    protocol::transport::Tcp,
};
use std::time::Duration;

fn timing(capture: &Capture) -> stats::TcpTimingStat {
    let mut collector =
        stats::Collector::for_table(Duration::from_secs(1), stats::Table::TcpTiming).unwrap();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Default::default(),
        |record| {
            collector.observe(&record);
            Ok::<_, BoundaryError>(())
        },
    )
    .unwrap();
    collector.finish(&run).tcp_timing.remove(0)
}

#[test]
fn nonoverlapping_reordered_segments_each_produce_an_rtt_sample() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    let mut later = capture.client_spec(&stream, Tcp::ACK);
    later.sequence += 3;
    capture.push(later, b"def");
    capture.client(&mut stream, b"abc");
    stream.client_sequence += 3;
    capture.server(&mut stream, b"");
    let report = timing(&capture);
    assert_eq!(report.ack_rtt_a_to_b.count, 3); // SYN and both data segments.
    assert_eq!(report.ack_rtt_a_to_b.excluded_retransmission, 0);
    assert_eq!(report.ack_rtt_a_to_b.excluded_missing_ack, 0);
}

#[test]
fn fresh_syn_resets_pending_ranges_and_handshake_but_preserves_rtt_totals() {
    for flags in [Tcp::RST | Tcp::ACK, Tcp::FIN | Tcp::ACK] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.open(&mut stream);
        capture.client(&mut stream, b"abc");
        capture.push(capture.client_spec(&stream, flags), b"");
        // A higher sequence in the new connection would acknowledge old data
        // unless the pending ranges are cleared before processing this SYN.
        capture.reopen(&mut stream, 2000);
        capture.client(&mut stream, b"");
        let report = timing(&capture);
        assert_eq!(report.ack_rtt_a_to_b.count, 2);
        assert_eq!(report.ack_rtt_b_to_a.count, 2);
        assert_eq!(
            report.ack_rtt_a_to_b.excluded_missing_ack,
            1 + u64::from(flags & Tcp::FIN != 0)
        );
        assert_eq!(report.ack_rtt_a_to_b.excluded_retransmission, 0);
        assert_eq!(
            report.handshake_syn_to_syn_ack,
            Some(Duration::from_secs(1))
        );
        assert_eq!(report.handshake_syn_to_ack, Some(Duration::from_secs(2)));
    }
}
