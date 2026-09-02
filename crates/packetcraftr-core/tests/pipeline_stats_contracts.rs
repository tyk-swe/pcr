// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for the statistics collector.

mod common;

use common::{CLIENT, SERVER, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame};
use packetcraftr_core::analysis::{
    Error, IpFamilyCounters, IpReassemblyReport, Options, StreamTransport, Summary as RunSummary,
    run,
};
use packetcraftr_core::protocol::transport::Tcp;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn stats_collect_all_tables_with_directional_and_time_accounting() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            client_tcp(100, 0, Tcp::SYN, 2_000),
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 2_000),
            b"",
        ),
        udp_frame(
            &registry,
            epoch + Duration::from_secs(4),
            CLIENT,
            SERVER,
            9_999,
            9_999,
            b"datagram",
        ),
    ];
    let total_bytes = frames
        .iter()
        .map(|frame| u64::from(frame.captured_length()))
        .sum::<u64>();
    let tcp_bytes = u64::from(frames[0].captured_length()) + u64::from(frames[1].captured_length());
    let mut capture = reader(&frames);
    let mut collector = packetcraftr_core::analysis::stats::Collector::new(Duration::from_secs(1))
        .expect("valid interval");
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options::default(),
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .expect("statistics pass succeeds");
    let report = collector.finish(&summary);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(report.frames, 3);
    assert_eq!(report.bytes, total_bytes);
    assert_eq!(report.first_timestamp, Some(epoch + Duration::from_secs(1)));
    assert_eq!(report.last_timestamp, Some(epoch + Duration::from_secs(4)));
    assert_eq!(report.io.len(), 2);
    assert_eq!(report.io[0].offset, Duration::ZERO);
    assert_eq!(report.io[0].frames, 2);
    assert_eq!(report.io[1].offset, Duration::from_secs(2));
    assert_eq!(report.io[1].frames, 1);

    let ipv4 = report
        .protocols
        .iter()
        .find(|row| row.protocol == "ipv4")
        .expect("IPv4 protocol row");
    assert_eq!((ipv4.frames, ipv4.bytes), (3, total_bytes));
    assert_eq!(report.protocols[0].frames, 3);
    assert_eq!(report.conversations.len(), 2);
    let tcp = report
        .conversations
        .iter()
        .find(|row| row.transport == StreamTransport::Tcp)
        .expect("TCP conversation row");
    assert_eq!(tcp.stream, 0);
    assert_eq!(tcp.frames_a_to_b, 1);
    assert_eq!(tcp.frames_b_to_a, 1);
    assert_eq!(tcp.bytes_a_to_b + tcp.bytes_b_to_a, tcp_bytes);
    assert_eq!(tcp.duration(), Duration::from_secs(1));
    let udp = report
        .conversations
        .iter()
        .find(|row| row.transport == StreamTransport::Udp)
        .expect("UDP conversation row");
    assert_eq!(udp.stream, 0);
    assert_eq!(udp.frames_a_to_b, 1);
    assert_eq!(StreamTransport::Udp.as_str(), "udp");

    assert_eq!(report.endpoints.len(), 2);
    let client = report
        .endpoints
        .iter()
        .find(|row| row.address == IpAddr::V4(CLIENT))
        .expect("client endpoint");
    assert_eq!(client.tx_frames, 2);
    assert_eq!(client.rx_frames, 1);
    let udp_port = report
        .ports
        .iter()
        .find(|row| row.transport == StreamTransport::Udp && row.port == 9_999)
        .expect("UDP port row");
    assert_eq!(
        udp_port.frames, 1,
        "same source/destination port counts once"
    );
}

#[test]
fn stats_reject_zero_interval_and_empty_report_is_well_formed() {
    assert!(matches!(
        packetcraftr_core::analysis::stats::Collector::new(Duration::ZERO),
        Err(Error::InvalidLimit {
            field: "interval",
            value: 0,
            ..
        })
    ));
    let report = packetcraftr_core::analysis::stats::Collector::new(Duration::from_millis(250))
        .expect("valid interval")
        .finish(&RunSummary::default());
    assert_eq!(report.frames, 0);
    assert_eq!(report.bytes, 0);
    assert!(report.first_timestamp.is_none());
    assert!(report.protocols.is_empty());
    assert!(report.conversations.is_empty());
    assert!(report.io.is_empty());
    assert_eq!(report.ip_reassembly, IpReassemblyReport::default());

    let ip_reassembly = IpReassemblyReport {
        counters: packetcraftr_core::analysis::IpCounters {
            ipv4: IpFamilyCounters {
                physical_fragments: 2,
                completed_datagrams: 1,
                derived_datagram_bytes: 44,
                derived_payload_bytes: 24,
                ..IpFamilyCounters::default()
            },
            ..packetcraftr_core::analysis::IpCounters::default()
        },
        outcomes_omitted: 3,
        ..IpReassemblyReport::default()
    };
    let report = packetcraftr_core::analysis::stats::Collector::new(Duration::from_millis(250))
        .expect("valid interval")
        .finish(&RunSummary {
            ip_reassembly: ip_reassembly.clone(),
            ..RunSummary::default()
        });
    assert_eq!(report.ip_reassembly, ip_reassembly);
    assert_eq!(report.frames, 0);
    assert_eq!(report.bytes, 0);
}
