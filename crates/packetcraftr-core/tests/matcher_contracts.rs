// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::registry;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_core::layer::{Malformed, Raw};
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::network::{Fragment, HopByHop, Icmpv4, Icmpv6, Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Sctp, Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{Ah, Gre};
use packetcraftr_core::protocol::{
    BuiltinProtocol, IcmpErrorKind, QuotedTransport, quoted_icmp_error, transport_tuple_reversed,
};
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

    let matched = udp_matcher
        .matches(&request, &response)
        .expect("reverse UDP tuples attribute the response");
    assert_eq!(matched.confidence, 100);
    assert_eq!(
        udp_matcher.responder(&request, &response),
        Some(IpAddr::V4(IPV4_SERVER))
    );
    response.get_mut::<Udp>().expect("UDP").destination_port += 1;
    assert!(udp_matcher.matches(&request, &response).is_none());

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
    assert!(
        echo_matcher
            .matches(&echo_request, &echo_response)
            .is_some()
    );
    echo_response.get_mut::<Icmpv4>().expect("ICMP").code = 1;
    assert!(
        echo_matcher
            .matches(&echo_request, &echo_response)
            .is_none()
    );
}

#[test]
fn quoted_icmp_errors_classify_every_transport_in_both_address_families() {
    use IcmpErrorKind::{
        AdministrativelyProhibited, DestinationUnreachable, PortUnreachable, TimeExceeded,
    };
    use NetworkVersion::{V4, V6};
    use ProbeTransport::{Icmp, Sctp, Tcp, Udp};

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
            quoted_icmp_error(&request.packet, &response, transport.quoted()),
            Some(expected),
            "{network:?} {transport:?}"
        );

        if let Some(protocol) = transport.protocol() {
            let matched = registry
                .matcher(protocol)
                .expect("transport matcher")
                .matches(&request.packet, &response)
                .unwrap_or_else(|| panic!("{network:?} {transport:?} must correlate"));
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
        quoted_icmp_error(&request.packet, &response, QuotedTransport::Udp),
        Some(IcmpErrorKind::PortUnreachable)
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
            quoted_icmp_error(&request.packet, &response, QuotedTransport::Udp),
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
    let matched = matcher
        .matches(&request, &response)
        .expect("reverse SCTP tuples attribute the response");
    assert_eq!(matched.confidence, 200);
    assert_eq!(
        matcher.responder(&request, &response),
        Some(IpAddr::V4(IPV4_SERVER))
    );

    response.get_mut::<Sctp>().expect("SCTP").verification_tag += 1;
    assert!(matcher.matches(&request, &response).is_none());
    response.get_mut::<Sctp>().expect("SCTP").verification_tag = INITIATE_TAG;
    response.get_mut::<Raw>().expect("INIT ACK").bytes = init_chunk(1, 0xa0b0_c0d0);
    assert!(matcher.matches(&request, &response).is_none());
}

const DNS_PORT: u16 = 53;
const QUERY_FLAGS: u16 = 0x0100;
const RESPONSE_FLAGS: u16 = 0x8180;

fn dns_name_wire(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(u8::try_from(label.len()).expect("fixture label length"));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn dns_wire(id: u16, flags: u16, questions: &[(&str, u16, u16)]) -> Vec<u8> {
    let mut wire = id.to_be_bytes().to_vec();
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.extend_from_slice(
        &u16::try_from(questions.len())
            .expect("fixture question count")
            .to_be_bytes(),
    );
    wire.extend_from_slice(&[0; 6]);
    for (name, query_type, class) in questions {
        wire.extend_from_slice(&dns_name_wire(name));
        wire.extend_from_slice(&query_type.to_be_bytes());
        wire.extend_from_slice(&class.to_be_bytes());
    }
    wire
}

fn dns_response_wire(id: u16, questions: &[(&str, u16, u16)]) -> Vec<u8> {
    let mut wire = dns_wire(id, RESPONSE_FLAGS, questions);
    wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
    // The answer owner is the first question name when one exists, else the
    // root name.
    if questions.is_empty() {
        wire.push(0);
    } else {
        wire.extend_from_slice(&[0xc0, 0x0c]);
    }
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&60_u32.to_be_bytes());
    wire.extend_from_slice(&4_u16.to_be_bytes());
    wire.extend_from_slice(&[192, 0, 2, 53]);
    wire
}

fn dns_layer(wire: Vec<u8>) -> Dns {
    Dns::try_from(wire).expect("fixture DNS message")
}

fn dns_packet(source: Ipv4Addr, destination: Ipv4Addr, source_port: u16, dns: Dns) -> Packet {
    let mut packet = ipv4_envelope(source, destination);
    packet.push(Udp {
        source_port,
        destination_port: if source_port == DNS_PORT {
            CLIENT_PORT
        } else {
            DNS_PORT
        },
        ..Udp::default()
    });
    packet.push(dns);
    packet
}

fn dns_query_packet(id: u16, questions: &[(&str, u16, u16)]) -> Packet {
    dns_packet(
        IPV4_CLIENT,
        IPV4_SERVER,
        CLIENT_PORT,
        dns_layer(dns_wire(id, QUERY_FLAGS, questions)),
    )
}

fn dns_reply_packet(id: u16, questions: &[(&str, u16, u16)]) -> Packet {
    dns_packet(
        IPV4_SERVER,
        IPV4_CLIENT,
        DNS_PORT,
        dns_layer(dns_response_wire(id, questions)),
    )
}

const INNER_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const INNER_SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);

#[test]
fn dns_answers_match_their_query_at_application_confidence() {
    let registry = registry();
    let matcher = registry.matcher("dns").expect("DNS matcher");
    let request = dns_query_packet(0x1234, &[("example.com", 1, 1)]);
    let response = dns_reply_packet(0x1234, &[("example.com", 1, 1)]);

    let matched = matcher
        .matches(&request, &response)
        .expect("the DNS answer attributes to its query");
    assert_eq!(matched.confidence, 250);
    assert_eq!(
        matcher.responder(&request, &response),
        Some(IpAddr::V4(IPV4_SERVER))
    );

    // The typed DNS layer owns the pair: the weaker transport matcher cannot
    // also accept the response on tuple reversal alone.
    assert!(
        registry
            .matcher("udp")
            .expect("UDP matcher")
            .matches(&request, &response)
            .is_none()
    );
}

#[test]
fn dns_answers_reject_every_identity_mismatch() {
    let registry = registry();
    let matcher = registry.matcher("dns").expect("DNS matcher");
    let request = dns_query_packet(0x1234, &[("example.com", 1, 1)]);

    let mut wrong_id = dns_reply_packet(0x1235, &[("example.com", 1, 1)]);
    let mut wrong_name = dns_reply_packet(0x1234, &[("other.example", 1, 1)]);
    let mut wrong_type = dns_reply_packet(0x1234, &[("example.com", 28, 1)]);
    let mut wrong_class = dns_reply_packet(0x1234, &[("example.com", 1, 3)]);
    let mut query_direction = dns_packet(
        IPV4_SERVER,
        IPV4_CLIENT,
        DNS_PORT,
        dns_layer(dns_wire(0x1234, QUERY_FLAGS, &[("example.com", 1, 1)])),
    );
    let mut other_opcode = dns_packet(
        IPV4_SERVER,
        IPV4_CLIENT,
        DNS_PORT,
        dns_layer(dns_wire(
            0x1234,
            RESPONSE_FLAGS | (2 << 11),
            &[("example.com", 1, 1)],
        )),
    );
    let mut missing = dns_reply_packet(0x1234, &[]);
    let mut malformed = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    malformed.push(Udp {
        source_port: DNS_PORT,
        destination_port: CLIENT_PORT,
        ..Udp::default()
    });
    malformed.push(Malformed::new(
        Some("dns".to_owned()),
        Bytes::from_static(&[0x12, 0x34, 0x81]),
        "truncated DNS message",
    ));
    let mut undecoded = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    undecoded.push(Udp {
        source_port: DNS_PORT,
        destination_port: CLIENT_PORT,
        ..Udp::default()
    });
    undecoded.push(Raw::new(vec![0; 4]));

    for (name, response) in [
        ("transaction id", &mut wrong_id),
        ("question name", &mut wrong_name),
        ("question type", &mut wrong_type),
        ("question class", &mut wrong_class),
        ("reply direction", &mut query_direction),
        ("opcode", &mut other_opcode),
        ("missing questions", &mut missing),
        ("malformed layer", &mut malformed),
        ("undecoded payload", &mut undecoded),
    ] {
        assert!(
            matcher.matches(&request, response).is_none(),
            "{name} must not attribute"
        );
    }

    let mut reversed_request = dns_query_packet(0x1234, &[("example.com", 1, 1)]);
    reversed_request.get_mut::<Dns>().expect("DNS").response = true;
    let response = dns_reply_packet(0x1234, &[("example.com", 1, 1)]);
    assert!(
        matcher.matches(&reversed_request, &response).is_none(),
        "a response-shaped request has no query to answer"
    );

    // The question section compares completely and in order.
    let two_questions = dns_query_packet(0x1234, &[("a.example", 1, 1), ("z.example", 28, 1)]);
    let reordered = dns_reply_packet(0x1234, &[("z.example", 28, 1), ("a.example", 1, 1)]);
    let reechoed = dns_reply_packet(0x1234, &[("a.example", 1, 1), ("z.example", 28, 1)]);
    assert!(matcher.matches(&two_questions, &reordered).is_none());
    assert!(matcher.matches(&two_questions, &reechoed).is_some());
}

#[test]
fn dns_names_fold_ascii_case_and_compression_only() {
    let registry = registry();
    let matcher = registry.matcher("dns").expect("DNS matcher");

    let request = dns_query_packet(0x1234, &[("EXAMPLE.com", 1, 1)]);
    let response = dns_reply_packet(0x1234, &[("eXaMpLe.CoM", 1, 1)]);
    assert!(
        matcher.matches(&request, &response).is_some(),
        "ASCII letter case is not DNS identity"
    );

    // The second question name points at the first; a literal echo decodes to
    // the same wire name.
    let mut compressed_wire = dns_wire(0x1234, QUERY_FLAGS, &[("example.com", 1, 1)]);
    compressed_wire[4..6].copy_from_slice(&2_u16.to_be_bytes());
    compressed_wire.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    let mut request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    request.push(Udp {
        source_port: CLIENT_PORT,
        destination_port: DNS_PORT,
        ..Udp::default()
    });
    request.push(dns_layer(compressed_wire));
    let response = dns_reply_packet(0x1234, &[("example.com", 1, 1), ("example.com", 1, 1)]);
    assert!(
        matcher.matches(&request, &response).is_some(),
        "a compressed question name equals its literal echo"
    );
}

#[test]
fn dns_matching_stays_inside_its_reversed_udp_flow() {
    let registry = registry();
    let matcher = registry.matcher("dns").expect("DNS matcher");
    let request = dns_query_packet(0x1234, &[("example.com", 1, 1)]);

    let mut wrong_port = dns_reply_packet(0x1234, &[("example.com", 1, 1)]);
    wrong_port.get_mut::<Udp>().expect("UDP").source_port = 5353;
    assert!(matcher.matches(&request, &wrong_port).is_none());

    let mut wrong_peer = dns_reply_packet(0x1234, &[("example.com", 1, 1)]);
    wrong_peer.get_mut::<Ipv4>().expect("IPv4").source = IPV4_ROUTER;
    assert!(matcher.matches(&request, &wrong_peer).is_none());

    // A tunneled flow cannot let an inner DNS answer bypass an outer or inner
    // envelope that does not reverse.
    let tunneled =
        |outer: (Ipv4Addr, Ipv4Addr), inner: (Ipv4Addr, Ipv4Addr), source_port: u16, dns: Dns| {
            let mut packet = ipv4_envelope(outer.0, outer.1);
            packet.push(Gre::default());
            packet.push(Ipv4 {
                source: inner.0,
                destination: inner.1,
                ..Ipv4::default()
            });
            packet.push(Udp {
                source_port,
                destination_port: if source_port == DNS_PORT {
                    CLIENT_PORT
                } else {
                    DNS_PORT
                },
                ..Udp::default()
            });
            packet.push(dns);
            packet
        };
    let tunneled_request = tunneled(
        (IPV4_CLIENT, IPV4_SERVER),
        (INNER_CLIENT, INNER_SERVER),
        CLIENT_PORT,
        dns_layer(dns_wire(0x1234, QUERY_FLAGS, &[("example.com", 1, 1)])),
    );
    let tunneled_reply = |inner: (Ipv4Addr, Ipv4Addr), outer_source: Ipv4Addr| {
        tunneled(
            (outer_source, IPV4_CLIENT),
            inner,
            DNS_PORT,
            dns_layer(dns_response_wire(0x1234, &[("example.com", 1, 1)])),
        )
    };
    assert!(
        matcher
            .matches(
                &tunneled_request,
                &tunneled_reply((INNER_SERVER, INNER_CLIENT), IPV4_SERVER)
            )
            .is_some(),
        "a fully reversed tunnel still attributes"
    );
    assert!(
        matcher
            .matches(
                &tunneled_request,
                &tunneled_reply((INNER_CLIENT, INNER_SERVER), IPV4_SERVER)
            )
            .is_none(),
        "an inner flow that does not reverse cannot attribute"
    );
    assert!(
        matcher
            .matches(
                &tunneled_request,
                &tunneled_reply((INNER_SERVER, INNER_CLIENT), IPV4_ROUTER)
            )
            .is_none(),
        "an outer envelope that does not reverse cannot attribute"
    );
}

#[test]
fn transport_tuple_reversed_correlates_udp_while_deeper_layers_stay_opaque() {
    let request = dns_query_packet(0x1234, &[("example.com", 1, 1)]);

    // Tuple correlation answers even where the DNS matcher rejects identity:
    // dedicated workflows classify the payload themselves.
    let mismatched = dns_reply_packet(0x1235, &[("other.example", 1, 1)]);
    assert_eq!(
        transport_tuple_reversed(&request, &mismatched, BuiltinProtocol::Udp),
        Some(IpAddr::V4(IPV4_SERVER))
    );
    let mut malformed = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
    malformed.push(Udp {
        source_port: DNS_PORT,
        destination_port: CLIENT_PORT,
        ..Udp::default()
    });
    malformed.push(Malformed::new(
        Some("dns".to_owned()),
        Bytes::from_static(&[0x12, 0x34, 0x81]),
        "truncated DNS message",
    ));
    assert_eq!(
        transport_tuple_reversed(&request, &malformed, BuiltinProtocol::Udp),
        Some(IpAddr::V4(IPV4_SERVER))
    );

    let mut wrong_port = dns_reply_packet(0x1234, &[("example.com", 1, 1)]);
    wrong_port.get_mut::<Udp>().expect("UDP").source_port = 5353;
    assert!(transport_tuple_reversed(&request, &wrong_port, BuiltinProtocol::Udp).is_none());

    // TCP stays eligible for transports other than UDP, and a request with no
    // UDP layer has no tuple to reverse.
    let mut tcp_request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    tcp_request.push(Tcp {
        source_port: CLIENT_PORT,
        destination_port: SERVER_PORT,
        ..Tcp::default()
    });
    assert!(transport_tuple_reversed(&tcp_request, &mismatched, BuiltinProtocol::Udp).is_none());
}

#[test]
fn dns_over_tcp_retains_sequence_aware_transport_ownership() {
    let registry = registry();
    let mut request = ipv4_envelope(IPV4_CLIENT, IPV4_SERVER);
    request.push(Tcp {
        source_port: CLIENT_PORT,
        destination_port: DNS_PORT,
        sequence: 100,
        flags: Tcp::ACK,
        ..Tcp::default()
    });
    request.push(dns_layer(dns_wire(
        0x1234,
        QUERY_FLAGS,
        &[("example.com", 1, 1)],
    )));
    let request = build_packet(request).packet;
    let acknowledgment = 100 + u32::try_from(request.encoded_payload_length(1).unwrap()).unwrap();
    for with_dns in [false, true] {
        let mut response = ipv4_envelope(IPV4_SERVER, IPV4_CLIENT);
        response.push(Tcp {
            source_port: DNS_PORT,
            destination_port: CLIENT_PORT,
            acknowledgment,
            flags: Tcp::ACK,
            ..Tcp::default()
        });
        if with_dns {
            response.push(dns_layer(dns_response_wire(
                0x1234,
                &[("example.com", 1, 1)],
            )));
        }
        let matcher = registry.matcher("tcp").unwrap();
        assert_eq!(
            matcher.matches(&request, &response).unwrap().confidence,
            200
        );
        assert!(
            registry
                .matcher("dns")
                .unwrap()
                .matches(&request, &response)
                .is_none()
        );
        response.get_mut::<Tcp>().unwrap().acknowledgment += 1;
        assert!(matcher.matches(&request, &response).is_none());
    }
}
