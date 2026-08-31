// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::follow::Collector as FollowCollector;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::analysis::reassembly::ip::{
    Family, IncompleteDatagram, IncompleteReason, OverlapPolicy, ResourceError,
};
use packetcraftr_core::analysis::{
    IpDatagramOutcome, IpEvent, IpEventRecord, Limits, Options, run_with_ip_events,
};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Padding, Raw};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::ipv6::{DestinationOptions, Fragment as Ipv6Fragment};
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{Ah, Vxlan};

#[allow(dead_code)]
#[path = "common/tls_frames.rs"]
mod tls_frames;

const UDP_DATA: &[u8] = b"abcdefghijklmnop";
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

fn registry() -> Arc<packetcraftr_core::registry::Registry> {
    packetcraftr_core::protocol::builtin::registry()
}

fn build(registry: &Arc<packetcraftr_core::registry::Registry>, packet: Packet) -> Bytes {
    Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("fragment fixture builds")
        .bytes
}

fn ipv4_fragments(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 2] {
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let payload = complete.get(20..).expect("fixed IPv4 header");
    let epoch = SystemTime::UNIX_EPOCH;
    [
        ipv4_fragment_frame(registry, epoch, 0, true, &payload[..16]),
        ipv4_fragment_frame(
            registry,
            epoch + Duration::from_secs(1),
            2,
            false,
            &payload[16..],
        ),
    ]
}

fn ipv4_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        identification: 42,
        more_fragments: more,
        fragment_offset: offset,
        protocol: WireValue::Exact(17),
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet)).expect("valid IPv4 frame")
}

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

fn tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    sequence: u32,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet)).expect("valid TCP frame")
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

#[allow(clippy::too_many_arguments)]
fn ipv4_protocol_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    identification: u16,
    protocol: u8,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        identification,
        more_fragments: more,
        fragment_offset: offset,
        protocol: WireValue::Exact(protocol),
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet)).expect("valid protocol fragment")
}

fn encapsulated_ipv4_fragments(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    identification: u16,
    gre_key: u32,
    start: SystemTime,
) -> [Frame; 2] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: outer_source,
        destination: outer_destination,
        ..Ipv4::default()
    });
    complete.push(Gre {
        key: Some(gre_key),
        ..Gre::default()
    });
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let payload = complete.get(20..).expect("fixed outer IPv4 header");
    let first_length = 24;
    [
        outer_ipv4_fragment_frame(
            registry,
            start,
            outer_source,
            outer_destination,
            identification,
            0,
            true,
            &payload[..first_length],
        ),
        outer_ipv4_fragment_frame(
            registry,
            start + Duration::from_secs(1),
            outer_source,
            outer_destination,
            identification,
            u16::try_from(first_length / 8).expect("fixture offset fits"),
            false,
            &payload[first_length..],
        ),
    ]
}

fn doubly_fragmented_gre_udp_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 4] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let inner_payload = complete.get(20..).expect("fixed inner IPv4 header");

    let outer_datagram =
        |timestamp, outer_identification, inner_offset, inner_more, payload: &[u8]| {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv4::default()
            });
            packet.push(Gre {
                key: Some(42),
                ..Gre::default()
            });
            packet.push(Ipv4 {
                identification: 84,
                more_fragments: inner_more,
                fragment_offset: inner_offset,
                protocol: WireValue::Exact(17),
                source: CLIENT,
                destination: SERVER,
                ..Ipv4::default()
            });
            packet.push(Raw::new(payload.to_vec()));
            let packet = build(registry, packet);
            let outer_payload = packet.get(20..).expect("fixed outer IPv4 header");
            let first_length = 24;
            [
                outer_ipv4_fragment_frame(
                    registry,
                    timestamp,
                    outer_source,
                    outer_destination,
                    outer_identification,
                    0,
                    true,
                    &outer_payload[..first_length],
                ),
                outer_ipv4_fragment_frame(
                    registry,
                    timestamp + Duration::from_secs(1),
                    outer_source,
                    outer_destination,
                    outer_identification,
                    u16::try_from(first_length / 8).expect("fixture offset fits"),
                    false,
                    &outer_payload[first_length..],
                ),
            ]
        };
    let [first_outer, first_outer_tail] =
        outer_datagram(SystemTime::UNIX_EPOCH, 100, 0, true, &inner_payload[..16]);
    let [second_outer, second_outer_tail] = outer_datagram(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        101,
        2,
        false,
        &inner_payload[16..],
    );
    [
        first_outer,
        first_outer_tail,
        second_outer,
        second_outer_tail,
    ]
}

fn scope_isolated_nested_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 4] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let middle_source = Ipv4Addr::new(203, 0, 113, 10);
    let middle_destination = Ipv4Addr::new(203, 0, 113, 11);
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let inner_payload = complete.get(20..).expect("fixed inner IPv4 header");

    let carrier = |timestamp, outer_key, inner_offset, inner_more, inner_fragment: &[u8]| {
        let mut middle = Packet::new();
        middle.push(Ipv4 {
            source: middle_source,
            destination: middle_destination,
            ..Ipv4::default()
        });
        middle.push(Gre {
            key: Some(42),
            ..Gre::default()
        });
        middle.push(Ipv4 {
            identification: 84,
            more_fragments: inner_more,
            fragment_offset: inner_offset,
            protocol: WireValue::Exact(17),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        middle.push(Raw::new(inner_fragment.to_vec()));
        let middle = build(registry, middle);
        let middle_payload = middle.get(20..).expect("fixed middle IPv4 header");
        let first_length = 24;
        let fragment = |at, offset, more, bytes: &[u8]| {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv4::default()
            });
            packet.push(Gre {
                key: Some(outer_key),
                ..Gre::default()
            });
            packet.push(Ipv4 {
                identification: 100,
                more_fragments: more,
                fragment_offset: offset,
                protocol: WireValue::Exact(47),
                source: middle_source,
                destination: middle_destination,
                ..Ipv4::default()
            });
            packet.push(Raw::new(bytes.to_vec()));
            Frame::new(at, LinkType::IPV4, build(registry, packet))
                .expect("valid scope-isolated carrier fragment")
        };
        [
            fragment(timestamp, 0, true, &middle_payload[..first_length]),
            fragment(
                timestamp + Duration::from_secs(1),
                u16::try_from(first_length / 8).expect("fixture offset fits"),
                false,
                &middle_payload[first_length..],
            ),
        ]
    };

    let [first, first_tail] = carrier(SystemTime::UNIX_EPOCH, 1, 0, true, &inner_payload[..16]);
    let [second, second_tail] = carrier(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        2,
        2,
        false,
        &inner_payload[16..],
    );
    [first, first_tail, second, second_tail]
}

fn inner_tcp_payload(registry: &Arc<packetcraftr_core::registry::Registry>) -> Bytes {
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
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    build(registry, complete).slice(20..)
}

fn inner_udp_payload(registry: &Arc<packetcraftr_core::registry::Registry>) -> Bytes {
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    build(registry, complete).slice(20..)
}

fn cascading_vxlan_tcp_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 4] {
    let inner_payload = inner_tcp_payload(registry);
    let outer_source = CLIENT;
    let outer_destination = SERVER;
    let carrier =
        |timestamp, outer_identification, inner_offset, inner_more, inner_fragment: &[u8]| {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv4::default()
            });
            packet.push(Udp {
                source_port: 50_000,
                destination_port: 4_789,
                ..Udp::default()
            });
            packet.push(Vxlan {
                vni: 42,
                ..Vxlan::default()
            });
            packet.push(Ethernet::default());
            packet.push(Ipv4 {
                identification: 84,
                more_fragments: inner_more,
                fragment_offset: inner_offset,
                protocol: WireValue::Exact(6),
                source: CLIENT,
                destination: SERVER,
                ..Ipv4::default()
            });
            packet.push(Raw::new(inner_fragment.to_vec()));
            let packet = build(registry, packet);
            let outer_payload = packet.get(20..).expect("fixed outer IPv4 header");
            let first_length = 40;
            [
                ipv4_protocol_fragment_frame(
                    registry,
                    timestamp,
                    outer_identification,
                    17,
                    0,
                    true,
                    &outer_payload[..first_length],
                ),
                ipv4_protocol_fragment_frame(
                    registry,
                    timestamp + Duration::from_secs(1),
                    outer_identification,
                    17,
                    u16::try_from(first_length / 8).expect("fixture offset fits"),
                    false,
                    &outer_payload[first_length..],
                ),
            ]
        };
    let [first, first_tail] = carrier(SystemTime::UNIX_EPOCH, 100, 0, true, &inner_payload[..24]);
    let [second, second_tail] = carrier(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        101,
        3,
        false,
        &inner_payload[24..],
    );
    [first, first_tail, second, second_tail]
}

fn vxlan_inner_tcp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_payload = inner_tcp_payload(registry);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            identification: 84,
            more_fragments: more,
            fragment_offset: offset,
            protocol: WireValue::Exact(6),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &inner_payload[..24]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            3,
            false,
            &inner_payload[24..],
        ),
    ]
}

fn vxlan_inner_udp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_payload = inner_udp_payload(registry);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            identification: 84,
            more_fragments: more,
            fragment_offset: offset,
            protocol: WireValue::Exact(17),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN UDP fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &inner_payload[..16]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            false,
            &inner_payload[16..],
        ),
    ]
}

fn vxlan_inner_ipv6_extension_udp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source: inner_source,
        destination: inner_destination,
        ..Ipv6::default()
    });
    complete.push(DestinationOptions::default());
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(40..);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        });
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(60),
            fragment_offset: offset,
            more_fragments: more,
            identification: 84,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN IPv6 extension fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &fragmentable[..16]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            false,
            &fragmentable[16..],
        ),
    ]
}

fn vxlan_inner_ipv6_extension_tcp_fragment_frames_nonzero_first(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source: inner_source,
        destination: inner_destination,
        ..Ipv6::default()
    });
    complete.push(DestinationOptions::default());
    complete.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 100,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(40..);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        });
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(60),
            fragment_offset: offset,
            more_fragments: more,
            identification: 85,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN IPv6 extension fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 3, false, &fragmentable[24..]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            0,
            true,
            &fragmentable[..24],
        ),
    ]
}

fn with_invalid_outer_udp_checksum(frame: &Frame) -> Frame {
    let mut bytes = frame.bytes().to_vec();
    let checksum = bytes
        .get_mut(26)
        .expect("fixed IPv4 and UDP headers contain a checksum");
    *checksum ^= 1;
    Frame::new(
        frame.timestamp.expect("fixture has a timestamp"),
        frame.link_type,
        bytes,
    )
    .expect("checksum mutation keeps the frame structurally valid")
}

#[allow(clippy::too_many_arguments)]
fn outer_ipv4_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        identification,
        more_fragments: more,
        fragment_offset: offset,
        protocol: WireValue::Exact(47),
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
        .expect("valid outer IPv4 fragment")
}

fn ipv6_fragments(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 2] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let payload = complete.get(40..).expect("fixed IPv6 header");
    let epoch = SystemTime::UNIX_EPOCH;
    [
        ipv6_fragment_frame(
            registry,
            epoch,
            source,
            destination,
            0,
            true,
            &payload[..16],
        ),
        ipv6_fragment_frame(
            registry,
            epoch + Duration::from_secs(1),
            source,
            destination,
            2,
            false,
            &payload[16..],
        ),
    ]
}

fn ipv6_ah_tcp_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 3] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let ah = Ah {
        spi: 0x1020_3040,
        ..Ah::default()
    };
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(ah.clone());
    complete.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 100,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(64..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(ah.clone());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(6),
            fragment_offset: offset,
            more_fragments: more,
            identification: 43,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid AH-prefixed IPv6 fragment")
    };
    [
        Frame::new(epoch, LinkType::IPV6, complete).expect("valid unfragmented AH frame"),
        fragment(epoch + Duration::from_secs(1), 0, true, &fragmentable[..24]),
        fragment(
            epoch + Duration::from_secs(2),
            3,
            false,
            &fragmentable[24..],
        ),
    ]
}

fn ipv6_ah_gre_tcp_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 3] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let ah = Ah {
        spi: 0x1020_3040,
        ..Ah::default()
    };
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(ah.clone());
    complete.push(Gre {
        key: Some(42),
        ..Gre::default()
    });
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
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(64..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(ah.clone());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(47),
            fragment_offset: offset,
            more_fragments: more,
            identification: 45,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid AH-prefixed tunneled IPv6 fragment")
    };
    let first_length = 32;
    [
        Frame::new(epoch, LinkType::IPV6, complete).expect("valid unfragmented tunneled frame"),
        fragment(
            epoch + Duration::from_secs(1),
            0,
            true,
            &fragmentable[..first_length],
        ),
        fragment(
            epoch + Duration::from_secs(2),
            u16::try_from(first_length / 8).expect("fixture offset fits"),
            false,
            &fragmentable[first_length..],
        ),
    ]
}

fn with_nonzero_ah_reserved(frame: &Frame) -> Frame {
    let mut bytes = frame.bytes().to_vec();
    bytes
        .get_mut(42..44)
        .expect("fixed IPv6 and AH headers")
        .copy_from_slice(&[0, 1]);
    Frame::new(
        frame.timestamp.expect("fixture has a timestamp"),
        frame.link_type,
        bytes,
    )
    .expect("mutated AH frame remains valid")
}

fn ipv6_destination_options_fragments(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(DestinationOptions::default());
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(48..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(DestinationOptions::default());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(17),
            fragment_offset: offset,
            more_fragments: more,
            identification: 44,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid destination-options IPv6 fragment")
    };
    [
        fragment(epoch, 0, true, &fragmentable[..16]),
        fragment(
            epoch + Duration::from_secs(1),
            2,
            false,
            &fragmentable[16..],
        ),
    ]
}

fn atomic_ipv6_frame(registry: &Arc<packetcraftr_core::registry::Registry>) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("documentation source"),
        destination: "2001:db8::2".parse().expect("documentation destination"),
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Auto,
        fragment_offset: 0,
        more_fragments: false,
        identification: 7,
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(UDP_DATA));
    Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::IPV6,
        build(registry, packet),
    )
    .expect("valid atomic fragment frame")
}

fn ipv6_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    source: std::net::Ipv6Addr,
    destination: std::net::Ipv6Addr,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Exact(17),
        fragment_offset: offset,
        more_fragments: more,
        identification: 42,
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV6, build(registry, packet)).expect("valid IPv6 frame")
}

fn reader(link_type: LinkType, frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).expect("capture writer initializes");
    for frame in frames {
        writer.write_frame(frame).expect("fragment frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fragment capture opens")
}

fn assert_derived_udp(link_type: LinkType, family: Family, frames: &[Frame]) {
    let registry = registry();
    let filter_source = match family {
        Family::Ipv4 => "ip.frag_offset == 2 && udp.stream == 0",
        Family::Ipv6 => "frag6.offset == 2 && udp.stream == 0",
    };
    let filter = Filter::compile(
        filter_source,
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("stream filter compiles");
    let mut capture = reader(link_type, frames);
    let mut events = Vec::new();
    let mut observed = Vec::new();
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ip_overlap: OverlapPolicy::Reject,
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |record| {
            let derived = record.derived().expect("completion has a derived view");
            observed.push((
                record.number,
                record.decoded.frame.captured_length(),
                derived.decoded.frame.captured_length(),
                derived.decoded.original.len(),
                record.udp_stream,
                derived.fragment_count,
                derived.payload_bytes,
            ));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented UDP analysis succeeds");

    assert_eq!(summary.frames_read, 2);
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, 2);
    assert_eq!(observed[0].1, frames[1].captured_length());
    let derived_length = match family {
        Family::Ipv4 => 44,
        Family::Ipv6 => 64,
    };
    assert_eq!(observed[0].2, derived_length);
    assert_eq!(usize::try_from(observed[0].2).unwrap(), observed[0].3);
    assert_eq!(observed[0].4, Some(0));
    assert_eq!(observed[0].5, 2);
    assert_eq!(observed[0].6, 24);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);

    let counters = match family {
        Family::Ipv4 => &summary.ip_reassembly.counters.ipv4,
        Family::Ipv6 => &summary.ip_reassembly.counters.ipv6,
    };
    assert_eq!(counters.physical_fragments, 2);
    assert_eq!(counters.admitted_fragments, 2);
    assert_eq!(counters.completing_fragments, 1);
    assert_eq!(counters.completed_datagrams, 1);
    assert_eq!(counters.derived_payload_bytes, 24);
    assert_eq!(summary.ip_reassembly.outcomes.len(), 1);
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 2,
            event: IpEvent::Outcome(IpDatagramOutcome::Completed { .. })
        }]
    ));
}

#[test]
fn ipv4_completion_is_a_derived_filtered_udp_view_on_one_physical_record() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    assert_derived_udp(LinkType::IPV4, Family::Ipv4, &frames);
}

#[test]
fn ipv6_completion_removes_fragment_header_and_dispatches_udp() {
    let registry = registry();
    let frames = ipv6_fragments(&registry);
    assert_derived_udp(LinkType::IPV6, Family::Ipv6, &frames);
}

#[test]
fn ipv6_ah_prefix_reuses_unfragmented_tcp_scope() {
    let registry = registry();
    let frames = ipv6_ah_tcp_frames(&registry);
    let mut capture = reader(LinkType::IPV6, &frames);
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.tcp_flow.is_some() {
            observed.push((
                record.derived().is_some(),
                record.tcp_stream,
                record.tcp_flow.map(|flow| flow.scope),
            ));
        }
        Ok(())
    })
    .expect("AH-prefixed fragments analyze");

    assert_eq!(observed.len(), 2);
    assert!(!observed[0].0);
    assert!(observed[1].0);
    assert_eq!(observed[0].1, Some(0));
    assert_eq!(observed[1].1, Some(0));
    assert_eq!(observed[0].2, observed[1].2);
}

#[test]
fn ipv6_ah_prefix_keeps_order_for_derived_tunneled_tcp_scope() {
    let registry = registry();
    let frames = ipv6_ah_gre_tcp_frames(&registry);
    let mut capture = reader(LinkType::IPV6, &frames);
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.tcp_flow.is_some() {
            observed.push((record.tcp_stream, record.tcp_flow.map(|flow| flow.scope)));
        }
        Ok(())
    })
    .expect("AH-prefixed tunneled fragments analyze");

    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0], observed[1]);
}

#[test]
fn expert_reports_replayed_ah_diagnostic_once_on_completing_fragment() {
    let registry = registry();
    let source = ipv6_ah_tcp_frames(&registry);
    let frames = [
        with_nonzero_ah_reserved(&source[1]),
        with_nonzero_ah_reserved(&source[2]),
    ];
    let mut capture = reader(LinkType::IPV6, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            findings.extend(expert.observe(&record));
            Ok(())
        })
        .expect("AH diagnostics analyze");
    let (trailing, expert_summary) = expert.finish(&summary);
    findings.extend(trailing);
    let ah_findings = findings
        .iter()
        .filter(|finding| finding.code == "decode.ah_reserved")
        .collect::<Vec<_>>();

    assert_eq!(ah_findings.len(), 2);
    assert_eq!(ah_findings[0].number, 1);
    assert_eq!(ah_findings[1].number, 2);
    assert!(ah_findings.iter().all(|finding| finding.stream.is_none()));
    assert_eq!(
        expert_summary.codes.get("decode.ah_reserved").copied(),
        Some(2)
    );
}

#[test]
fn derived_filter_layers_exclude_replayed_ipv6_prefix() {
    let registry = registry();
    let frames = ipv6_destination_options_fragments(&registry);
    let filter = Filter::compile(
        "ipv6_destination_options#2",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("occurrence filter compiles");
    let mut capture = reader(LinkType::IPV6, &frames);
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |_| panic!("one physical destination-options header must not match occurrence two"),
    )
    .expect("destination-options fragments analyze");

    assert_eq!(summary.frames_matched, 0);
    assert_eq!(summary.ip_reassembly.counters.ipv6.completed_datagrams, 1);
}

#[test]
fn atomic_ipv6_fragment_keeps_single_frame_dispatch_unchanged() {
    let registry = registry();
    let frame = atomic_ipv6_frame(&registry);
    let mut capture = reader(LinkType::IPV6, std::slice::from_ref(&frame));
    let mut observed = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            observed.push((record.derived().is_none(), record.udp_stream));
            Ok(())
        })
        .expect("atomic fragment analyzes without reassembly");

    assert_eq!(observed, [(true, Some(0))]);
    assert_eq!(summary.ip_reassembly.counters.ipv6.physical_fragments, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv6.atomic_fragments, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv6.admitted_fragments, 0);
    assert!(summary.ip_reassembly.outcomes.is_empty());
}

#[test]
fn eof_incomplete_event_is_capture_global_even_when_filter_matches_no_frame() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let filter = Filter::compile(
        "udp",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("UDP filter compiles");
    let mut capture = reader(LinkType::IPV4, &frames[..1]);
    let mut events = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| panic!("opaque fragment must not match UDP"),
    )
    .expect("incomplete capture reports rather than failing");

    assert_eq!(summary.frames_read, 1);
    assert_eq!(summary.frames_matched, 0);
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 1,
            event: IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
                reason: IncompleteReason::EndOfCapture,
                fragment_count: 1,
                unique_bytes: 16,
                known_final_length: None,
                ..
            }))
        }]
    ));
}

#[test]
fn eof_ip_sink_cannot_overrun_analysis_deadline() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let mut capture = reader(LinkType::IPV4, &frames[..1]);
    let max_duration = Duration::from_millis(250);
    let mut event_delivered = false;
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_duration,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| {
            event_delivered = true;
            std::thread::sleep(max_duration);
            Ok(())
        },
        |_| Ok(()),
    );

    assert!(
        event_delivered,
        "the incomplete event must reach the EOF sink"
    );
    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::DurationLimit { limit, .. })
            if limit == max_duration
    ));
}

#[test]
fn ip_event_batch_stops_when_sink_exhausts_analysis_deadline() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let payload = [1_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(&registry, epoch, 1, 17, 0, true, &payload),
        ipv4_protocol_fragment_frame(&registry, epoch, 2, 17, 0, true, &payload),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            100,
            b"advance capture time",
        ),
    ];
    let mut capture = reader(LinkType::IPV4, &frames);
    let max_duration = Duration::from_millis(250);
    let mut events_delivered = 0;
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_duration,
                ip_idle_expiry: Duration::from_secs(1),
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| {
            events_delivered += 1;
            std::thread::sleep(max_duration);
            Ok(())
        },
        |_| Ok(()),
    );

    assert_eq!(events_delivered, 1);
    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::DurationLimit { limit, .. })
            if limit == max_duration
    ));
}

#[test]
fn eof_events_and_outcomes_share_the_configured_retention_cap() {
    let registry = registry();
    let payload = [1_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(&registry, SystemTime::UNIX_EPOCH, 1, 17, 0, true, &payload),
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            17,
            0,
            true,
            &payload,
        ),
    ];
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_outcomes: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| Ok(()),
    )
    .expect("bounded EOF retirement succeeds");

    assert_eq!(summary.ip_reassembly.counters.ipv4.incomplete_datagrams, 2);
    assert_eq!(summary.ip_reassembly.outcomes.len(), 1);
    assert_eq!(summary.ip_reassembly.outcomes_omitted, 1);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].event,
        IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
            reason: IncompleteReason::EndOfCapture,
            ..
        }))
    ));
}

#[test]
fn derived_inner_transports_extend_scope_with_gre_identity() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let first = encapsulated_ipv4_fragments(&registry, 42, 1, epoch);
    let second = encapsulated_ipv4_fragments(&registry, 43, 2, epoch + Duration::from_secs(2));
    let frames = [
        first[0].clone(),
        first[1].clone(),
        second[0].clone(),
        second[1].clone(),
    ];
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut completed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.derived().is_some() {
            completed.push((
                record.number,
                record.udp_stream,
                record.udp_flow.map(|flow| flow.scope),
            ));
        }
        Ok(())
    })
    .expect("encapsulated fragmented datagrams analyze");

    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].0, 2);
    assert_eq!(completed[0].1, Some(0));
    assert_eq!(completed[1].0, 4);
    assert_eq!(completed[1].1, Some(1));
    assert_ne!(completed[0].2, completed[1].2);
}

#[test]
fn derived_inner_fragments_reenter_reassembly_and_dispatch_udp() {
    let registry = registry();
    let frames = doubly_fragmented_gre_udp_frames(&registry);
    let filter = Filter::compile(
        "udp.stream == 0",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("UDP stream filter compiles");
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let mut observed = Vec::new();
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |record| {
            let derived = record
                .derived()
                .expect("inner completion has a derived view");
            observed.push((
                record.number,
                record.udp_stream,
                derived.fragment_count,
                derived.payload_bytes,
            ));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("nested fragmented UDP analysis succeeds");

    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(observed, [(4, Some(0), 2, 24)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
    assert_eq!(summary.ip_reassembly.counters.ipv4.physical_fragments, 6);
    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 3);
    assert!(!events.iter().any(|record| matches!(
        record.event,
        IpEvent::Outcome(IpDatagramOutcome::Incomplete { .. })
    )));
    assert_eq!(
        events
            .iter()
            .filter(|record| matches!(
                record.event,
                IpEvent::Outcome(IpDatagramOutcome::Completed { .. })
            ))
            .map(|record| record.number)
            .collect::<Vec<_>>(),
        [2, 4, 4]
    );
}

#[test]
fn nested_fragments_keep_the_parent_tunnel_scope() {
    let registry = registry();
    let frames = scope_isolated_nested_fragment_frames(&registry);
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut observed = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            observed.push((
                record.number,
                record.derived_datagrams().len(),
                record.udp_stream,
            ));
            Ok(())
        })
        .expect("nested fragments in distinct tunnel scopes analyze");

    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 2);
    assert_eq!(summary.ip_reassembly.counters.ipv4.incomplete_datagrams, 2);
    assert_eq!(
        summary.ip_reassembly.counters.ipv4.end_of_capture_datagrams,
        2
    );
    assert!(observed.iter().all(|(_, _, stream)| stream.is_none()));
    assert_eq!(observed[1].1, 1);
    assert_eq!(observed[3].1, 1);
}

#[test]
fn cascading_completions_preserve_intermediate_layers_and_streams() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let filter = Filter::compile(
        "udp.stream == 0 && tcp.stream == 0 && vxlan && tcp",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("cascade filter compiles");
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut observed = Vec::new();
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |record| {
            observed.push((
                record.number,
                record.derived_datagrams().len(),
                record.udp_stream,
                record.tcp_stream,
                record.udp_decoded.packet.get::<Vxlan>().is_some(),
                record.tcp_decoded.packet.get::<Tcp>().is_some(),
            ));
            Ok(())
        },
    )
    .expect("cascading completions analyze");

    assert_eq!(summary.frames_matched, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 3);
    assert_eq!(observed, [(4, 2, Some(0), Some(0), true, true)]);
}

#[test]
fn fragmented_udp_inside_udp_defers_the_same_kind_carrier_stream() {
    let registry = registry();
    let frames = vxlan_inner_udp_fragment_frames(&registry);
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut observed = Vec::new();
    let mut chunks = Vec::new();
    packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            observed.push((record.number, record.udp_stream, record.derived().is_some()));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("same-kind fragmented tunnel fits one flow slot");

    assert_eq!(observed, [(1, None, false), (2, Some(0), true)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
}

#[test]
fn fragmented_ipv6_extension_udp_defers_the_same_kind_carrier_stream() {
    let registry = registry();
    let frames = vxlan_inner_ipv6_extension_udp_fragment_frames(&registry);
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut observed = Vec::new();
    let mut chunks = Vec::new();
    packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            observed.push((record.number, record.udp_stream, record.derived().is_some()));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented extension-chain UDP fits one flow slot");

    assert_eq!(observed, [(1, None, false), (2, Some(0), true)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
}

#[test]
fn derived_cascade_bytes_share_the_aggregate_reassembly_budget() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let mut capture = reader(LinkType::IPV4, &frames[..2]);
    let limit = 26_200;
    let result = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: limit,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    );

    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                ResourceError::AggregateMemoryLimit { limit: 26_200 }
            )
        })
    ));
}

#[test]
fn derived_decode_metadata_shares_the_aggregate_reassembly_budget() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let mut capture = reader(LinkType::IPV4, &frames);
    let result = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: 5_000,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    );

    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                ResourceError::AggregateMemoryLimit { limit: 5_000 }
            )
        })
    ));
}

#[test]
fn budget_reduced_derived_layer_limit_keeps_resource_classification() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let mut capture = reader(LinkType::IPV4, &frames[..2]);
    let error = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_reassembly_bytes: 10_000,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
    )
    .expect_err("the derived VXLAN stack exceeds its budget-reduced layer cap");

    assert!(matches!(
        &error,
        packetcraftr_core::analysis::Error::IpReassembly {
            number: 2,
            source: packetcraftr_core::analysis::reassembly::ip::Error::Resource(
                ResourceError::AggregateMemoryLimit { limit: 10_000 }
            )
        }
    ));
    assert_eq!(
        error.classification().code,
        "policy.analysis_resource_limit"
    );
}

#[test]
fn idle_expiry_is_delivered_before_a_failing_fragment_push() {
    let registry = registry();
    let first_payload = [1_u8; 8];
    let failing_payload = [2_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH,
            1,
            17,
            0,
            true,
            &first_payload,
        ),
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(2),
            2,
            17,
            1,
            true,
            &failing_payload,
        ),
    ];
    let limits = Limits {
        max_ip_bytes_per_datagram: 8,
        ip_idle_expiry: Duration::from_secs(1),
        ..Limits::default()
    };
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits,
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| Ok(()),
    );

    assert!(
        result.is_err(),
        "the second fragment must exceed its byte limit"
    );
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 2,
            event: IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
                reason: IncompleteReason::IdleExpired,
                ..
            }))
        }]
    ));
}

#[test]
fn physical_udp_diagnostic_keeps_its_stream_on_inner_completion() {
    let registry = registry();
    let mut frames = vxlan_inner_tcp_fragment_frames(&registry);
    frames[1] = with_invalid_outer_udp_checksum(&frames[1]);
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        findings.extend(expert.observe(&record));
        Ok(())
    })
    .expect("diagnostic carrier frames analyze");
    let udp_checksum = findings
        .iter()
        .filter(|finding| finding.code == "decode.udp_checksum")
        .collect::<Vec<_>>();

    assert_eq!(udp_checksum.len(), 1);
    assert_eq!(udp_checksum[0].number, 2);
    assert_eq!(
        udp_checksum[0].stream,
        Some(StreamRef {
            transport: StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn unresolved_ipv6_extension_fragment_keeps_cross_kind_carrier_stream() {
    let registry = registry();
    let mut frames = vxlan_inner_ipv6_extension_tcp_fragment_frames_nonzero_first(&registry);
    frames[0] = with_invalid_outer_udp_checksum(&frames[0]);
    let mut capture = reader(LinkType::IPV4, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        observed.push((
            record.number,
            record.udp_stream,
            record.tcp_stream,
            record.derived().is_some(),
        ));
        findings.extend(expert.observe(&record));
        Ok(())
    })
    .expect("nonzero-first extension fragments analyze");
    let udp_checksum = findings
        .iter()
        .filter(|finding| finding.code == "decode.udp_checksum")
        .collect::<Vec<_>>();

    assert_eq!(
        observed,
        [(1, Some(0), None, false), (2, Some(0), Some(0), true),]
    );
    assert_eq!(udp_checksum.len(), 1);
    assert_eq!(udp_checksum[0].number, 1);
    assert_eq!(
        udp_checksum[0].stream,
        Some(StreamRef {
            transport: StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn partial_ipv6_extension_fragment_does_not_read_link_padding() {
    let registry = registry();
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(203, 0, 113, 1),
        destination: Ipv4Addr::new(203, 0, 113, 2),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 50_000,
        destination_port: 4_789,
        ..Udp::default()
    });
    packet.push(Vxlan {
        vni: 42,
        ..Vxlan::default()
    });
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: inner_source,
        destination: inner_destination,
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Exact(60),
        fragment_offset: 0,
        more_fragments: true,
        identification: 86,
    });
    // The fragment carries one Destination Options header that points to a
    // second one. The link padding must not supply that second header.
    packet.push(Raw::new(vec![60, 0, 0, 0, 0, 0, 0, 0]));
    packet.push(Padding::new(vec![17, 0, 0, 0, 0, 0, 0, 0]));
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::IPV4,
        build(&registry, packet),
    )
    .expect("valid padded IPv6 fragment carrier");
    let mut capture = reader(LinkType::IPV4, &[frame]);
    let mut observed = Vec::new();

    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        observed.push((
            record.udp_stream,
            record.tcp_stream,
            record.derived().is_some(),
        ));
        Ok(())
    })
    .expect("padded partial extension fragment analyzes");

    assert_eq!(observed, [(Some(0), None, false)]);
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
    let mut capture = reader(LinkType::IPV4, &frames);
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
    use packetcraftr_core::analysis::tls::{Collector, Limits as TlsLimits, Status};
    use tls_frames::{
        ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello,
    };

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
    let mut capture = reader(LinkType::IPV4, &frames);
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
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(31),
            100,
            b"tcp remains independently tracked",
        ),
    ];
    let mut capture = reader(LinkType::IPV4, &frames);
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
        tcp_frame(&registry, epoch, 100, b"first"),
        ipv4_fragment_frame(
            &registry,
            epoch + Duration::from_secs(300),
            0,
            true,
            b"filtered",
        ),
        tcp_frame(&registry, epoch + Duration::from_secs(1), 105, b"second"),
    ];
    let mut capture = reader(LinkType::IPV4, &frames);
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
