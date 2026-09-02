// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for fragmented TCP segments feeding TCP reassembly, follow,
//! expert, and TLS collectors.

mod common;

use common::ip_fragments::{
    UDP_DATA, build, client_ack_frame, ipv4_fragment_frame, ipv4_fragments,
    ipv4_protocol_fragment_frame, reader_with_link_type,
};
use common::{CLIENT, SERVER, registry};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::Options;
use packetcraftr_core::analysis::follow::Collector as FollowCollector;
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn ipv4_tcp_fragments(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 2] {
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 100,
        flags: Tcp::ACK,
        window: 0,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let payload = complete.get(20..).expect("fixed IPv4 header");
    let epoch = SystemTime::UNIX_EPOCH;
    [
        ipv4_protocol_fragment_frame(registry, epoch, 84, 6, 0, true, &payload[..24]),
        ipv4_protocol_fragment_frame(
            registry,
            epoch + Duration::from_secs(1),
            84,
            6,
            3,
            false,
            &payload[24..],
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn fragmented_tcp_datagram(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    identification: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    payload: &[u8],
) -> [Frame; 2] {
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    complete.push(Tcp {
        source_port,
        destination_port,
        sequence,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(payload.to_vec()));
    let complete = build(registry, complete);
    let ip_payload = complete.get(20..).expect("fixed IPv4 header");
    let first_length = 64;
    assert!(
        ip_payload.len() > first_length,
        "TLS fixture spans fragments"
    );
    let fragment = |at, offset, more, bytes: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            identification,
            more_fragments: more,
            fragment_offset: offset,
            protocol: WireValue::Exact(6),
            source,
            destination,
            ..Ipv4::default()
        });
        packet.push(Raw::new(bytes.to_vec()));
        Frame::new(at, LinkType::IPV4, build(registry, packet)).expect("valid TCP fragment")
    };
    [
        fragment(timestamp, 0, true, &ip_payload[..first_length]),
        fragment(
            timestamp + Duration::from_secs(1),
            u16::try_from(first_length / 8).expect("fixture offset fits"),
            false,
            &ip_payload[first_length..],
        ),
    ]
}

#[test]
fn fragmented_tcp_completion_feeds_tcp_follow_and_expert() {
    let registry = registry();
    let frames = ipv4_tcp_fragments(&registry);
    let filter = Filter::compile(
        "ip.frag_offset == 3 && tcp.stream == 0",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("combined physical and derived TCP filter compiles");
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    });
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut chunks = Vec::new();
    let mut findings = Vec::new();
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            chunks.extend(follow.observe(&record));
            findings.extend(expert.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented TCP analysis succeeds");
    let follow_summary = follow.finish(&summary);
    let (trailing_findings, _) = expert.finish(&summary);
    findings.extend(trailing_findings);

    assert_eq!(summary.frames_read, 2);
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
    assert_eq!(follow_summary.client_bytes, UDP_DATA.len() as u64);
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "tcp.zero_window"),
        "derived TCP header must reach expert analysis"
    );
}

#[test]
fn fragmented_tcp_segments_assemble_a_tls_session() {
    use common::tls_frames::{
        ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello,
    };
    use packetcraftr_core::analysis::tls::{Collector, Limits as TlsLimits, Status};

    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let client_payload = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let server_payload = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let client = fragmented_tcp_datagram(
        &registry,
        epoch,
        100,
        CLIENT,
        SERVER,
        40_000,
        443,
        1_000,
        &client_payload,
    );
    let server = fragmented_tcp_datagram(
        &registry,
        epoch + Duration::from_secs(2),
        101,
        SERVER,
        CLIENT,
        443,
        40_000,
        5_000,
        &server_payload,
    );
    let frames = [
        client[0].clone(),
        client[1].clone(),
        server[0].clone(),
        server[1].clone(),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut collector = Collector::new(TlsLimits::default());
    let mut sessions = Vec::new();
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            sessions.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented TLS capture analyzes");
    let (trailing, _) = collector.finish(&summary);
    sessions.extend(trailing);

    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 2);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session.status, Status::Complete);
    assert_eq!(
        sessions[0]
            .session
            .client
            .as_ref()
            .and_then(|client| client.sni.as_deref()),
        Some("api.example.test")
    );
}

#[test]
fn ip_expiry_and_tcp_state_keep_separate_limits_and_terminal_evidence() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let fragments = ipv4_fragments(&registry);
    let frames = [
        fragments[0].clone(),
        client_ack_frame(
            &registry,
            epoch + Duration::from_secs(31),
            100,
            b"tcp remains independently tracked",
        ),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            tcp_events: true,
            limits: packetcraftr_core::analysis::Limits {
                max_flows: 1,
                max_ip_datagrams: 1,
                ip_idle_expiry: Duration::from_secs(30),
                ..packetcraftr_core::analysis::Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect("IP and TCP state coexist under separate limits");

    assert_eq!(
        summary.ip_reassembly.counters.ipv4.idle_expired_datagrams,
        1
    );
    assert_eq!(
        summary.ip_reassembly.counters.ipv4.end_of_capture_datagrams,
        0
    );
    assert!(summary.trailing_tcp_events.iter().any(|event| matches!(
        event,
        packetcraftr_core::analysis::reassembly::tcp::Event::Evicted { .. }
    )));
}

#[test]
fn filtered_frames_do_not_advance_tcp_expiry_time() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let filter = Filter::compile(
        "tcp",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("TCP filter compiles");
    let frames = [
        client_ack_frame(&registry, epoch, 100, b"first"),
        ipv4_fragment_frame(
            &registry,
            epoch + Duration::from_secs(300),
            0,
            true,
            b"filtered",
        ),
        client_ack_frame(&registry, epoch + Duration::from_secs(1), 105, b"second"),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut matched_events = Vec::new();
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            tcp_events: true,
            ..Options::default()
        },
        |record| {
            matched_events.push((record.number, record.tcp_events.to_vec()));
            Ok(())
        },
    )
    .expect("out-of-order filtered timestamps analyze");

    assert_eq!(summary.frames_matched, 2);
    assert_eq!(matched_events.len(), 2);
    assert_eq!(matched_events[1].0, 3);
    assert!(matched_events[1].1.iter().all(|event| !matches!(
        event,
        packetcraftr_core::analysis::reassembly::tcp::Event::Evicted { .. }
    )));
    assert_eq!(
        summary
            .trailing_tcp_events
            .iter()
            .filter(|event| matches!(
                event,
                packetcraftr_core::analysis::reassembly::tcp::Event::Evicted { .. }
            ))
            .count(),
        1
    );
}
