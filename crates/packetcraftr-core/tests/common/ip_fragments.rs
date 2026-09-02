// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fragmented IPv4/IPv6 capture fixtures shared by the IP pipeline contracts.

use super::{CLIENT, SERVER};
use bytes::Bytes;
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub(crate) const UDP_DATA: &[u8] = b"abcdefghijklmnop";

pub(crate) fn build(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    packet: Packet,
) -> Bytes {
    Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("fragment fixture builds")
        .bytes
}

pub(crate) fn ipv4_fragments(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 2] {
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

pub(crate) fn ipv4_fragment_frame(
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

pub(crate) fn client_ack_frame(
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
pub(crate) fn ipv4_protocol_fragment_frame(
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

pub(crate) fn inner_tcp_payload(registry: &Arc<packetcraftr_core::registry::Registry>) -> Bytes {
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

pub(crate) fn cascading_vxlan_tcp_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 4] {
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

pub(crate) fn reader_with_link_type(
    link_type: LinkType,
    frames: &[Frame],
) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).expect("capture writer initializes");
    for frame in frames {
        writer.write_frame(frame).expect("fragment frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fragment capture opens")
}
