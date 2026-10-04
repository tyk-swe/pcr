// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::registry;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::network::{Icmpv4, Icmpv6, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::{QuotedTransport, quoted_icmp_error};
use packetcraftr_core::{build, codec, packet::Packet};

const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const IPV4_ROUTER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2);
const IPV6_ROUTER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 9);
const CLIENT_PORT: u16 = 40_000;
const SERVER_PORT: u16 = 33434;
const INITIATE_TAG: u32 = 0x0102_0304;

#[derive(Clone, Copy, Debug)]
enum NetworkVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug)]
enum ProbeTransport {
    Tcp,
    Udp,
    Sctp,
    Icmp,
}

impl ProbeTransport {
    const fn quoted(self) -> QuotedTransport {
        match self {
            Self::Tcp => QuotedTransport::Tcp,
            Self::Udp => QuotedTransport::Udp,
            Self::Sctp => QuotedTransport::Sctp,
            Self::Icmp => QuotedTransport::Icmp,
        }
    }

    const fn protocol(self) -> Option<&'static str> {
        match self {
            Self::Tcp => Some("tcp"),
            Self::Udp => Some("udp"),
            Self::Sctp => Some("sctp"),
            Self::Icmp => None,
        }
    }
}

fn ipv4_envelope(source: Ipv4Addr, destination: Ipv4Addr) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    packet
}

fn ipv6_envelope(source: Ipv6Addr, destination: Ipv6Addr) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    packet
}

fn init_chunk(chunk_type: u8, initiate_tag: u32) -> Bytes {
    let mut chunk = vec![chunk_type, 0, 0, 20];
    chunk.extend_from_slice(&initiate_tag.to_be_bytes());
    chunk.extend_from_slice(&[0, 0, 4, 0, 0, 10, 0, 10, 0, 1, 0, 1]);
    Bytes::from(chunk)
}

fn build_probe(network: NetworkVersion, transport: ProbeTransport) -> build::BuiltPacket {
    let mut packet = match network {
        NetworkVersion::V4 => ipv4_envelope(IPV4_CLIENT, IPV4_SERVER),
        NetworkVersion::V6 => ipv6_envelope(IPV6_CLIENT, IPV6_SERVER),
    };
    match transport {
        ProbeTransport::Tcp => {
            packet.push(Tcp {
                source_port: CLIENT_PORT,
                destination_port: SERVER_PORT,
                sequence: 0x1234_5678,
                ..Tcp::default()
            });
        }
        ProbeTransport::Udp => {
            packet.push(Udp {
                source_port: CLIENT_PORT,
                destination_port: SERVER_PORT,
                ..Udp::default()
            });
        }
        ProbeTransport::Sctp => {
            packet.push(Sctp {
                source_port: CLIENT_PORT,
                destination_port: SERVER_PORT,
                ..Sctp::default()
            });
            packet.push(Raw::new(init_chunk(1, INITIATE_TAG)));
        }
        ProbeTransport::Icmp => {
            match network {
                NetworkVersion::V4 => packet.push(Icmpv4 {
                    body: Bytes::from_static(&[0x12, 0x34, 0, 1, 0xaa]),
                    ..Icmpv4::default()
                }),
                NetworkVersion::V6 => packet.push(Icmpv6 {
                    body: Bytes::from_static(&[0x12, 0x34, 0, 1, 0xaa]),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    build_packet(packet)
}

fn build_packet(packet: Packet) -> build::BuiltPacket {
    build::Builder::new(registry())
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("packet fixture must build")
}

fn mutated(bytes: &Bytes, mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    mutate(&mut bytes);
    bytes
}

fn quoted_response(network: NetworkVersion, quote: &[u8], icmp_type: u8, code: u8) -> Packet {
    let mut body = vec![0; 4];
    body.extend_from_slice(quote);
    match network {
        NetworkVersion::V4 => {
            let mut response = ipv4_envelope(IPV4_ROUTER, IPV4_CLIENT);
            response.push(Icmpv4 {
                icmp_type,
                code,
                body: Bytes::from(body),
                ..Icmpv4::default()
            });
            response
        }
        NetworkVersion::V6 => {
            let mut response = ipv6_envelope(IPV6_ROUTER, IPV6_CLIENT);
            response.push(Icmpv6 {
                icmp_type,
                code,
                body: Bytes::from(body),
                ..Icmpv6::default()
            });
            response
        }
    }
}

#[test]
fn quoted_icmp_reject_bad_inexact_ipv4_probes() {
    let request = build_probe(NetworkVersion::V4, ProbeTransport::Tcp);
    let variants = [
        (
            "truncated header",
            mutated(&request.bytes, |q| q.truncate(19)),
        ),
        (
            "short header length",
            mutated(&request.bytes, |q| q[0] = 0x44),
        ),
        (
            "short total length",
            mutated(&request.bytes, |q| {
                q[2..4].copy_from_slice(&27_u16.to_be_bytes());
            }),
        ),
        (
            "non-initial fragment",
            mutated(&request.bytes, |q| {
                q[6..8].copy_from_slice(&1_u16.to_be_bytes());
            }),
        ),
    ];

    let mut variants = variants.to_vec();
    for (name, index) in [
        ("source address", 12),
        ("destination address", 16),
        ("protocol", 9),
        ("source port", 20),
        ("TCP sequence", 24),
    ] {
        let mut quote = request.bytes.to_vec();
        quote[index] ^= 1;
        variants.push((name, quote));
    }

    for (name, quote) in variants {
        let response = quoted_response(NetworkVersion::V4, &quote, 3, 13);
        assert_eq!(
            quoted_icmp_error(&request.packet, &response, QuotedTransport::Tcp,),
            None,
            "{name}"
        );
    }

    let response = quoted_response(NetworkVersion::V4, &request.bytes, 3, 13);
    assert_eq!(
        quoted_icmp_error(&request.packet, &response, QuotedTransport::Udp),
        None,
        "declared transport must match the request"
    );
    let non_error = quoted_response(NetworkVersion::V4, &request.bytes, 8, 0);
    assert_eq!(
        quoted_icmp_error(&request.packet, &non_error, QuotedTransport::Tcp,),
        None,
        "echo request is not an ICMP error"
    );
}
