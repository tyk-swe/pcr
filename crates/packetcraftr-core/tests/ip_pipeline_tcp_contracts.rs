// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::ip_fragments::{
    UDP_DATA, build, client_ack_frame, ipv4_fragments, ipv4_protocol_fragment_frame,
    reader_with_link_type,
};
use common::{CLIENT, SERVER, registry};
use packetcraftr_core::analysis::Options;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
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

#[expect(
    clippy::too_many_arguments,
    reason = "fixture builder mirrors the wire fields"
)]
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
fn ip_expiry_terminal_ev() {
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
                ip: packetcraftr_core::analysis::reassembly::ip::Limits {
                    max_datagrams: 1,
                    idle_expiry: Duration::from_secs(30),
                    ..packetcraftr_core::analysis::reassembly::ip::Limits::default()
                },
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
