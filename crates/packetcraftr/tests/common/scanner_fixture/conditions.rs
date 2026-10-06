// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unreachable_pub)]

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::build;
use packetcraftr_core::codec;
use packetcraftr_core::decode;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Icmpv4, Icmpv6, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};

use super::providers::{Condition, FamilyAddresses};

pub fn respond(condition: Condition, addresses: FamilyAddresses, sent: &[u8]) -> Vec<Vec<u8>> {
    match condition {
        Condition::Responsive => direct_reply(sent, addresses, ReplyKind::Responsive)
            .into_iter()
            .collect(),
        Condition::Closed => direct_reply(sent, addresses, ReplyKind::Refused)
            .into_iter()
            .collect(),
        Condition::Blocked => icmp_error(sent, addresses, true).into_iter().collect(),
        Condition::Silent => Vec::new(),
        Condition::Malformed => vec![vec![if addresses.source.is_ipv4() {
            0x45
        } else {
            0x60
        }]],
        Condition::Unrelated => direct_reply(sent, addresses, ReplyKind::Unrelated)
            .into_iter()
            .collect(),
    }
}

enum ReplyKind {
    Responsive,
    Refused,
    Unrelated,
}

fn direct_reply(sent: &[u8], addresses: FamilyAddresses, kind: ReplyKind) -> Option<Vec<u8>> {
    let decoded = decode_frame(sent)?;
    let packet = &decoded.packet;
    let icmp_unreachable = matches!(kind, ReplyKind::Refused);
    if let Some(tcp) = packet.get::<Tcp>() {
        let (destination_port, flags) = match kind {
            ReplyKind::Responsive => (tcp.source_port, Tcp::SYN | Tcp::ACK),
            ReplyKind::Refused => (tcp.source_port, Tcp::RST | Tcp::ACK),
            ReplyKind::Unrelated => (different_port(tcp.source_port), Tcp::SYN | Tcp::ACK),
        };
        return Some(finish(
            addresses,
            |reply| {
                reply.push(Tcp {
                    source_port: tcp.destination_port,
                    destination_port,
                    sequence: 0,
                    acknowledgment: tcp.sequence.wrapping_add(1),
                    flags,
                    ..Tcp::default()
                });
            },
            addresses.destination,
        ));
    }
    if let Some(udp) = packet.get::<Udp>() {
        if icmp_unreachable {
            return icmp_error(sent, addresses, false);
        }
        let destination_port = match kind {
            ReplyKind::Unrelated => different_port(udp.source_port),
            _ => udp.source_port,
        };
        let payload = udp_payload(packet);
        return Some(finish(
            addresses,
            |reply| {
                reply.push(Udp {
                    source_port: udp.destination_port,
                    destination_port,
                    ..Udp::default()
                });
                if !payload.is_empty() {
                    reply.push(packetcraftr_core::layer::Raw::new(payload));
                }
            },
            addresses.destination,
        ));
    }
    if let Some(icmpv4) = packet.get::<Icmpv4>() {
        if icmp_unreachable {
            return icmp_error(sent, addresses, false);
        }
        let body = match kind {
            ReplyKind::Unrelated => altered_identity(&icmpv4.body),
            _ => icmpv4.body.clone(),
        };
        return Some(finish(
            addresses,
            |reply| {
                reply.push(Icmpv4 {
                    icmp_type: 0,
                    body,
                    ..Icmpv4::default()
                });
            },
            addresses.destination,
        ));
    }
    if let Some(icmpv6) = packet.get::<Icmpv6>() {
        if icmp_unreachable {
            return icmp_error(sent, addresses, false);
        }
        let body = match kind {
            ReplyKind::Unrelated => altered_identity(&icmpv6.body),
            _ => icmpv6.body.clone(),
        };
        return Some(finish(
            addresses,
            |reply| {
                reply.push(Icmpv6 {
                    icmp_type: 129,
                    body,
                    ..Icmpv6::default()
                });
            },
            addresses.destination,
        ));
    }
    None
}

fn icmp_error(sent: &[u8], addresses: FamilyAddresses, router: bool) -> Option<Vec<u8>> {
    decode_frame(sent)?;
    let source = if router {
        addresses.router
    } else {
        addresses.destination
    };
    let mut quote = vec![0_u8; 4];
    quote.extend_from_slice(sent);
    let quote = Bytes::from(quote);
    Some(match addresses.source {
        IpAddr::V4(_) => finish(
            addresses,
            |reply| {
                reply.push(Icmpv4 {
                    icmp_type: 3,
                    code: if router { 13 } else { 3 },
                    body: quote,
                    ..Icmpv4::default()
                });
            },
            source,
        ),
        IpAddr::V6(_) => finish(
            addresses,
            |reply| {
                reply.push(Icmpv6 {
                    icmp_type: 1,
                    code: if router { 1 } else { 4 },
                    body: quote,
                    ..Icmpv6::default()
                });
            },
            source,
        ),
    })
}

fn finish(
    addresses: FamilyAddresses,
    transport: impl FnOnce(&mut Packet),
    source: IpAddr,
) -> Vec<u8> {
    let mut reply = Packet::new();
    match (addresses.source, addresses.destination) {
        (IpAddr::V4(source_local), IpAddr::V4(_)) => {
            reply.push(Ipv4 {
                source: match source {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => unreachable!("v4 fixture"),
                },
                destination: source_local,
                identification: 1,
                ..Ipv4::default()
            });
        }
        (IpAddr::V6(source_local), IpAddr::V6(_)) => {
            reply.push(Ipv6 {
                source: match source {
                    IpAddr::V6(v6) => v6,
                    IpAddr::V4(_) => unreachable!("v6 fixture"),
                },
                destination: source_local,
                ..Ipv6::default()
            });
        }
        _ => unreachable!("fixture families are homogeneous"),
    }
    transport(&mut reply);
    build::Builder::new(builtin::registry())
        .build(reply, codec::Context::default(), build::Options::default())
        .expect("the fixture builds only valid replies")
        .bytes
        .to_vec()
}

fn decode_frame(sent: &[u8]) -> Option<decode::DecodedPacket> {
    let frame = Frame::new(
        std::time::SystemTime::now(),
        LinkType::RAW,
        Bytes::copy_from_slice(sent),
    )
    .ok()?;
    decode::Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .ok()
}

fn udp_payload(packet: &Packet) -> Bytes {
    packet
        .get::<packetcraftr_core::layer::Raw>()
        .map(|raw| raw.bytes.clone())
        .unwrap_or_default()
}

fn different_port(port: u16) -> u16 {
    port.wrapping_add(1)
}

fn altered_identity(body: &Bytes) -> Bytes {
    let mut body = body.to_vec();
    if let Some(byte) = body.first_mut() {
        *byte ^= 0xff;
    } else {
        body.push(0xff);
    }
    Bytes::from(body)
}
