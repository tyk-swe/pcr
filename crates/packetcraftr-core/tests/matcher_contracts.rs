// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::icmp::{Icmpv4, Icmpv6};
use packetcraftr_core::protocol::ipv6::{Fragment, HopByHop};
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Ah;
use packetcraftr_core::protocol::{
    QuotedIcmpError, QuotedProbeTransport, builtin, quoted_icmp_error_kind,
};
use packetcraftr_core::{Packet, build};

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
    const fn quoted(self) -> QuotedProbeTransport {
        match self {
            Self::Tcp => QuotedProbeTransport::Tcp,
            Self::Udp => QuotedProbeTransport::Udp,
            Self::Sctp => QuotedProbeTransport::Sctp,
            Self::Icmp => QuotedProbeTransport::Icmp,
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

fn registry() -> Arc<packetcraftr_core::registry::Registry> {
    Arc::new(builtin::registry().expect("built-in protocols must register"))
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
        .build(packet, build::Context::default(), build::Options::default())
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
fn reverse_udp_and_echo_matchers_require_reversed_identity() {
    let registry = registry();
    let udp_matcher = registry.matcher("udp").expect("UDP matcher");
    let mut request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    request.push(Udp {
        source_port: CLIENT_PORT,
        destination_port: SERVER_PORT,
        ..Udp::default()
    });
    request.push(Raw::new(vec![1]));
    let mut response = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    response.push(Udp {
        source_port: SERVER_PORT,
        destination_port: CLIENT_PORT,
        ..Udp::default()
    });
    response.push(Raw::new(vec![2]));

    let matched = udp_matcher.matches(&request, &response);
    assert!(matched.matched);
    assert_eq!(matched.confidence, 100);
    assert_eq!(
        udp_matcher.responder(&request, &response),
        Some(IpAddr::V4(IPV4_SERVER))
    );
    response.get_mut::<Udp>().expect("UDP").destination_port += 1;
    assert!(!udp_matcher.matches(&request, &response).matched);

    let echo_matcher = registry.matcher("icmpv4").expect("ICMPv4 matcher");
    let echo_body = Bytes::from_static(&[0x12, 0x34, 0, 1, 9]);
    let mut echo_request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    echo_request.push(Icmpv4 {
        body: echo_body.clone(),
        ..Icmpv4::default()
    });
    let mut echo_response = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    echo_response.push(Icmpv4 {
        icmp_type: 0,
        body: Bytes::from_static(&[0x12, 0x34, 0, 1, 7]),
        ..Icmpv4::default()
    });
    assert!(echo_matcher.matches(&echo_request, &echo_response).matched);
    echo_response.get_mut::<Icmpv4>().expect("ICMP").code = 1;
    assert!(!echo_matcher.matches(&echo_request, &echo_response).matched);
}

#[test]
fn quoted_icmp_errors_classify_every_transport_in_both_address_families() {
    use NetworkVersion::{V4, V6};
    use ProbeTransport::{Icmp, Sctp, Tcp, Udp};
    use QuotedIcmpError::{
        AdministrativelyProhibited, DestinationUnreachable, PortUnreachable, TimeExceeded,
    };

    let cases = [
        (V4, Udp, 3, 3, PortUnreachable),
        (V4, Tcp, 3, 13, AdministrativelyProhibited),
        (V4, Sctp, 3, 1, DestinationUnreachable),
        (V4, Icmp, 11, 0, TimeExceeded),
        (V6, Udp, 1, 4, PortUnreachable),
        (V6, Tcp, 1, 1, AdministrativelyProhibited),
        (V6, Sctp, 1, 0, DestinationUnreachable),
        (V6, Icmp, 3, 0, TimeExceeded),
    ];

    let registry = registry();
    for (network, transport, icmp_type, code, expected) in cases {
        let request = build_probe(network, transport);
        let response = quoted_response(network, &request.bytes, icmp_type, code);
        assert_eq!(
            quoted_icmp_error_kind(&request.packet, &response, transport.quoted()),
            Some(expected),
            "{network:?} {transport:?}"
        );

        if let Some(protocol) = transport.protocol() {
            let matched = registry
                .matcher(protocol)
                .expect("transport matcher")
                .matches(&request.packet, &response);
            assert!(matched.matched, "{network:?} {transport:?}");
            assert_eq!(matched.confidence, 150, "{network:?} {transport:?}");
        }
    }
}

#[test]
fn quoted_icmp_rejects_malformed_or_inexact_ipv4_probes() {
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
            quoted_icmp_error_kind(&request.packet, &response, QuotedProbeTransport::Tcp,),
            None,
            "{name}"
        );
    }

    let response = quoted_response(NetworkVersion::V4, &request.bytes, 3, 13);
    assert_eq!(
        quoted_icmp_error_kind(&request.packet, &response, QuotedProbeTransport::Udp),
        None,
        "declared transport must match the request"
    );
    let non_error = quoted_response(NetworkVersion::V4, &request.bytes, 8, 0);
    assert_eq!(
        quoted_icmp_error_kind(&request.packet, &non_error, QuotedProbeTransport::Tcp,),
        None,
        "echo request is not an ICMP error"
    );
}

#[test]
fn quoted_ipv6_walks_extensions_and_rejects_non_initial_fragments() {
    let mut packet = ipv6_envelope(IPV6_CLIENT, IPV6_SERVER);
    packet.push(HopByHop::default());
    packet.push(Fragment::default());
    packet.push(Ah::default());
    packet.push(Udp {
        source_port: CLIENT_PORT,
        destination_port: SERVER_PORT,
        ..Udp::default()
    });
    let request = build_packet(packet);

    let response = quoted_response(NetworkVersion::V6, &request.bytes, 1, 4);
    assert_eq!(
        quoted_icmp_error_kind(&request.packet, &response, QuotedProbeTransport::Udp),
        Some(QuotedIcmpError::PortUnreachable)
    );

    let malformed_quotes = [
        (
            "oversized options header",
            mutated(&request.bytes, |q| q[41] = u8::MAX),
        ),
        (
            "non-initial fragment",
            mutated(&request.bytes, |q| {
                q[50..52].copy_from_slice(&8_u16.to_be_bytes());
            }),
        ),
        (
            "oversized authentication header",
            mutated(&request.bytes, |q| q[57] = u8::MAX),
        ),
    ];

    for (name, quote) in malformed_quotes {
        let response = quoted_response(NetworkVersion::V6, &quote, 1, 4);
        assert_eq!(
            quoted_icmp_error_kind(&request.packet, &response, QuotedProbeTransport::Udp),
            None,
            "{name}"
        );
    }
}

#[test]
fn sctp_init_ack_requires_reversed_ports_and_the_initiate_tag() {
    let mut request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    request.push(Sctp {
        source_port: CLIENT_PORT,
        destination_port: SERVER_PORT,
        ..Sctp::default()
    });
    request.push(Raw::new(init_chunk(1, INITIATE_TAG)));

    let mut response = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    response.push(Sctp {
        source_port: SERVER_PORT,
        destination_port: CLIENT_PORT,
        verification_tag: INITIATE_TAG,
        ..Sctp::default()
    });
    response.push(Raw::new(init_chunk(2, 0xa0b0_c0d0)));

    let registry = registry();
    let matcher = registry.matcher("sctp").expect("SCTP matcher");
    let matched = matcher.matches(&request, &response);
    assert!(matched.matched);
    assert_eq!(matched.confidence, 200);
    assert_eq!(
        matcher.responder(&request, &response),
        Some(IpAddr::V4(IPV4_SERVER))
    );

    response.get_mut::<Sctp>().expect("SCTP").verification_tag += 1;
    assert!(!matcher.matches(&request, &response).matched);
    response.get_mut::<Sctp>().expect("SCTP").verification_tag = INITIATE_TAG;
    response.get_mut::<Raw>().expect("INIT ACK").bytes = init_chunk(1, 0xa0b0_c0d0);
    assert!(!matcher.matches(&request, &response).matched);
}
