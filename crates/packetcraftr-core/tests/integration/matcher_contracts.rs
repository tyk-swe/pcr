// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use crate::common;

use common::registry;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::network::{Icmpv4, Icmpv6, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::{
    IcmpErrorKind, QuotedTransport, SctpResponseKind, quoted_icmp_error, sctp_response_kind,
};
use packetcraftr_core::{build, codec, field::WireValue, packet::Packet};

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
fn empty_ipv6_protocol_quotes_ignore_padding_and_icmp_extensions() {
    for protocol in [0, 6, 47, 59, 60] {
        let mut packet = ipv6_envelope(IPV6_CLIENT, IPV6_SERVER);
        let ipv6 = packet.get_mut::<Ipv6>().unwrap();
        ipv6.next_header = WireValue::Exact(protocol);
        ipv6.flow_label = 0x12345;
        let request = build_packet(packet);
        let mut quote = request.bytes.to_vec();
        quote.resize(128, 0);
        // RFC 4884 extension header and an MPLS object, including checksum.
        quote.extend_from_slice(&[0x20, 0, 0xdd, 0xb6, 0, 8, 1, 1, 0, 0, 1, 0x40]);
        for (icmp_type, code, kind) in [
            (1, 1, IcmpErrorKind::AdministrativelyProhibited),
            (3, 0, IcmpErrorKind::TimeExceeded),
        ] {
            let mut response = quoted_response(NetworkVersion::V6, &quote, icmp_type, code);
            let icmp = response.get_mut::<Icmpv6>().unwrap();
            let mut body = icmp.body.to_vec();
            body[0] = 16; // 128 padded quote octets, in 64-bit words.
            icmp.body = Bytes::from(body);
            assert_eq!(
                quoted_icmp_error(&request.packet, &response, QuotedTransport::Ip),
                Some(kind)
            );
        }
        for index in [3, 5, 6] {
            let mut wrong = quote.clone();
            wrong[index] ^= 1;
            let response = quoted_response(NetworkVersion::V6, &wrong, 1, 1);
            assert_eq!(
                quoted_icmp_error(&request.packet, &response, QuotedTransport::Ip),
                None
            );
        }
        let short = quoted_response(NetworkVersion::V6, &quote[..39], 3, 0);
        assert_eq!(
            quoted_icmp_error(&request.packet, &short, QuotedTransport::Ip),
            None
        );
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

#[test]
fn sctp_cookie_echo_icmp_and_ip_protocol_quotes_correlate_strictly() {
    let reg = registry();
    let sctp_matcher = reg.matcher("sctp").expect("sctp matcher");

    // SCTP INIT matches INIT ACK, ABORT, and other valid chunks with the initiate tag.
    let init_request = build_probe(NetworkVersion::V4, ProbeTransport::Sctp);
    let mut abort_response = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    abort_response.push(Sctp {
        source_port: SERVER_PORT,
        destination_port: CLIENT_PORT,
        verification_tag: INITIATE_TAG,
        ..Sctp::default()
    });
    abort_response.push(Raw::new(Bytes::from_static(&[6, 1, 0, 4])));
    let abort_response = build_packet(abort_response);
    assert!(
        sctp_matcher
            .matches(&init_request.packet, &abort_response.packet)
            .is_some()
    );
    assert_eq!(
        sctp_response_kind(&abort_response.packet, 1),
        Some(SctpResponseKind::Abort)
    );

    // SCTP COOKIE ECHO correlates direct ABORT and quoted ICMP errors by verification tag.
    let mut cookie_echo = ipv6_envelope(IPV6_CLIENT, IPV6_SERVER);
    cookie_echo.push(Sctp {
        source_port: CLIENT_PORT,
        destination_port: SERVER_PORT,
        verification_tag: INITIATE_TAG,
        ..Sctp::default()
    });
    cookie_echo.push(Raw::new(Bytes::from_static(&[10, 0, 0, 8, 1, 2, 3, 4])));
    let cookie_echo = build_packet(cookie_echo);

    let mut cookie_abort = ipv6_envelope(IPV6_SERVER, IPV6_CLIENT);
    cookie_abort.push(Sctp {
        source_port: SERVER_PORT,
        destination_port: CLIENT_PORT,
        verification_tag: INITIATE_TAG,
        ..Sctp::default()
    });
    cookie_abort.push(Raw::new(Bytes::from_static(&[6, 1, 0, 4])));
    let cookie_abort = build_packet(cookie_abort);
    assert!(
        sctp_matcher
            .matches(&cookie_echo.packet, &cookie_abort.packet)
            .is_some()
    );

    let mut wrong_tag = ipv6_envelope(IPV6_SERVER, IPV6_CLIENT);
    wrong_tag.push(Sctp {
        source_port: SERVER_PORT,
        destination_port: CLIENT_PORT,
        verification_tag: INITIATE_TAG ^ 1,
        ..Sctp::default()
    });
    wrong_tag.push(Raw::new(Bytes::from_static(&[6, 1, 0, 4])));
    let wrong_tag = build_packet(wrong_tag);
    assert!(
        sctp_matcher
            .matches(&cookie_echo.packet, &wrong_tag.packet)
            .is_none()
    );

    let cookie_icmp = quoted_response(NetworkVersion::V6, &cookie_echo.bytes, 1, 1);
    assert_eq!(
        quoted_icmp_error(&cookie_echo.packet, &cookie_icmp, QuotedTransport::Sctp),
        Some(IcmpErrorKind::AdministrativelyProhibited)
    );

    // IPv4 and IPv6 empty-payload IP-protocol probes correlate protocol-unreachable errors.
    let mut ipv4_proto = Packet::new();
    ipv4_proto.push(Ipv4 {
        source: IPV4_CLIENT,
        destination: IPV4_SERVER,
        identification: 0x4242,
        protocol: WireValue::Exact(47),
        ..Ipv4::default()
    });
    let ipv4_proto = build_packet(ipv4_proto);
    let proto_unreach_v4 = quoted_response(NetworkVersion::V4, &ipv4_proto.bytes, 3, 2);
    assert_eq!(
        quoted_icmp_error(&ipv4_proto.packet, &proto_unreach_v4, QuotedTransport::Ip),
        Some(IcmpErrorKind::ProtocolUnreachable)
    );

    let mut ipv6_proto = Packet::new();
    ipv6_proto.push(Ipv6 {
        source: IPV6_CLIENT,
        destination: IPV6_SERVER,
        flow_label: 0x12345,
        next_header: WireValue::Exact(47),
        ..Ipv6::default()
    });
    let ipv6_proto = build_packet(ipv6_proto);
    let mut param_prob_body = vec![0, 0, 0, 6];
    param_prob_body.extend_from_slice(&ipv6_proto.bytes);
    let mut proto_unreach_v6 = ipv6_envelope(IPV6_SERVER, IPV6_CLIENT);
    proto_unreach_v6.push(Icmpv6 {
        icmp_type: 4,
        code: 1,
        body: Bytes::from(param_prob_body),
        ..Icmpv6::default()
    });
    assert_eq!(
        quoted_icmp_error(&ipv6_proto.packet, &proto_unreach_v6, QuotedTransport::Ip),
        Some(IcmpErrorKind::ProtocolUnreachable)
    );

    // ICMPv4 Timestamp (13 -> 14) and Netmask (17 -> 18) match by 4-byte identity.
    let icmp_matcher = reg.matcher("icmpv4").expect("icmpv4 matcher");
    for (req_type, resp_type, body_len) in [(13_u8, 14_u8, 16_usize), (17_u8, 18_u8, 8_usize)] {
        let mut req_body = vec![0x50, 0x43, 0x00, 0x07];
        req_body.resize(body_len, 0);
        let mut req = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
        req.push(Icmpv4 {
            icmp_type: req_type,
            code: 0,
            body: Bytes::from(req_body.clone()),
            ..Icmpv4::default()
        });
        let mut resp = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
        resp.push(Icmpv4 {
            icmp_type: resp_type,
            code: 0,
            body: Bytes::from(req_body),
            ..Icmpv4::default()
        });
        assert!(icmp_matcher.matches(&req, &resp).is_some());
    }
}
