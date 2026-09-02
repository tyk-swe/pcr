// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for TCP and UDP stream following.

mod common;

use common::{CLIENT, SERVER, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame};
use packetcraftr_core::analysis::follow::Direction as FollowDirection;
use packetcraftr_core::analysis::reassembly::tcp;
use packetcraftr_core::analysis::{
    Options, StreamRef, StreamTransport, Summary as RunSummary, run,
};
use packetcraftr_core::protocol::transport::Tcp;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn tcp_follow_delivers_gap_fill_in_order_and_classifies_both_directions() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 2_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(104, 0, Tcp::ACK, 2_000),
            b"def",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 0, Tcp::ACK, 2_000),
            b"abc",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            server_tcp(500, 107, Tcp::ACK, 2_000),
            b"xy",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("follow pass succeeds");
    let summary = collector.finish(&run_summary);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].number, 3);
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[0].bytes.as_ref(), b"abcdef");
    assert_eq!(chunks[1].direction, FollowDirection::ServerToClient);
    assert_eq!(chunks[1].bytes.as_ref(), b"xy");
    assert_eq!(summary.frames, 4);
    assert_eq!(summary.client_bytes, 6);
    assert_eq!(summary.server_bytes, 2);
    assert_eq!(summary.undelivered_bytes, 0);
    assert_eq!(
        summary
            .client_flow
            .as_ref()
            .expect("client established")
            .source,
        IpAddr::V4(CLIENT)
    );
}

#[test]
fn tcp_follow_deduplicates_fast_open_data_across_directional_close() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 8_192), b"A"),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(101, 501, Tcp::ACK, 8_192),
            b"A",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            client_tcp(102, 501, Tcp::FIN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(4),
            client_tcp(101, 501, Tcp::ACK, 8_192),
            b"A",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("Fast Open follow pass succeeds");
    let summary = collector.finish(&run_summary);

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[0].bytes.as_ref(), b"A");
    assert_eq!(summary.client_bytes, 1);
    assert_eq!(summary.server_bytes, 0);
}

#[test]
fn tcp_follow_starts_a_fresh_delivery_generation_for_four_tuple_reuse() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 8_192), b"A"),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 102, Tcp::SYN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(102, 501, Tcp::FIN | Tcp::ACK, 8_192),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(3),
            client_tcp(100, 0, Tcp::SYN, 8_192),
            b"B",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("reused four-tuple follow pass succeeds");
    let summary = collector.finish(&run_summary);

    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.bytes.as_ref())
            .collect::<Vec<_>>(),
        [b"A".as_slice(), b"B".as_slice()]
    );
    assert_eq!(summary.client_bytes, 2);
    assert_eq!(summary.server_bytes, 0);
}

#[test]
fn udp_follow_emits_empty_and_nonempty_datagrams_and_ignores_other_streams() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        udp_frame(&registry, epoch, CLIENT, SERVER, 4_000, 9_000, b"query"),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            SERVER,
            CLIENT,
            9_000,
            4_000,
            b"answer",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            CLIENT,
            SERVER,
            4_001,
            9_000,
            b"other",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options::default(),
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("UDP follow succeeds");
    let summary = collector.finish(&run_summary);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].bytes.as_ref(), b"query");
    assert_eq!(chunks[0].direction, FollowDirection::ClientToServer);
    assert_eq!(chunks[1].bytes.as_ref(), b"answer");
    assert_eq!(chunks[1].direction, FollowDirection::ServerToClient);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 5);
    assert_eq!(summary.server_bytes, 6);

    let empty = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 99,
    })
    .finish(&RunSummary::default());
    assert_eq!(empty.frames, 0);
    assert!(empty.client_flow.is_none());
}

#[test]
fn tcp_follow_reports_bytes_stranded_behind_a_gap_at_end() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 2_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(105, 0, Tcp::ACK, 2_000),
            b"late",
        ),
    ];
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let run_summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            assert!(collector.observe(&record).is_empty());
            Ok(())
        },
    )
    .expect("follow pass succeeds");
    assert!(
        run_summary
            .trailing_tcp_events
            .iter()
            .any(|event| matches!(event, tcp::Event::Gap { .. }))
    );
    let summary = collector.finish(&run_summary);
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 0);
    assert_eq!(summary.undelivered_bytes, 4);
}
