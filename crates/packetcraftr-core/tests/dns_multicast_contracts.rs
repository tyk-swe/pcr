// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::Ipv4Addr;
use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use common::registry;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Malformed, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::dns::{Dns, RecordValue};
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::{build, codec, decode};

const MDNS_PORT: u16 = 5_353;
const LLMNR_PORT: u16 = 5_355;
const CLIENT: [u8; 4] = [192, 0, 2, 10];
const RESPONDER: [u8; 4] = [192, 0, 2, 80];
const MDNS_GROUP: [u8; 4] = [224, 0, 0, 251];

/// `host.local A` with the unicast-response (QU) bit set in the class.
const MDNS_QU_QUERY: &[u8] =
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x05local\x00\x00\x01\x80\x01";
/// The matching response: id 0, no question section, cache-flush bit in the
/// answer's class.
const MDNS_RESPONSE: &[u8] = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04host\x05local\x00\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x50";
const LLMNR_QUERY: &[u8] =
    b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x00\x00\x01\x00\x01";

fn udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: impl Layer,
) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4(source, destination));
    packet.push(Udp {
        source_port,
        destination_port,
        ..Udp::default()
    });
    packet.push(payload);
    packet
}

fn dns(wire: &[u8]) -> Dns {
    Dns::try_from(wire.to_vec()).expect("fixture DNS message")
}

fn build_with(packet: Packet, mode: codec::Mode) -> build::BuiltPacket {
    build::Builder::new(registry())
        .build(
            packet,
            codec::Context::default(),
            build::Options {
                mode,
                ..build::Options::default()
            },
        )
        .expect("fixture builds")
}

fn dissect(bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    decode::Dissector::new(registry())
        .decode(frame, decode::Options::default())
        .unwrap()
}

fn protocols(decoded: &decode::DecodedPacket) -> Vec<&str> {
    decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect()
}

/// Builds `packet` strictly, dissects it and requires a strict rebuild of the
/// dissected packet to match, also after dropping the retained wire image so
/// the typed fields alone must reproduce every bit.
fn round_trip(packet: Packet) -> decode::DecodedPacket {
    let built = build_with(packet, codec::Mode::Strict);
    let decoded = dissect(built.bytes.clone());
    assert_eq!(protocols(&decoded), ["ipv4", "udp", "dns"]);
    assert_eq!(
        build_with(decoded.packet.clone(), codec::Mode::Strict).bytes,
        built.bytes
    );
    let mut retyped = decoded.packet.clone();
    retyped.get_mut::<Dns>().unwrap().edit(|_| {});
    assert_eq!(build_with(retyped, codec::Mode::Strict).bytes, built.bytes);
    decoded
}

#[test]
fn mdns_query_and_response_decode_as_dns_and_keep_the_class_bits() {
    let query = round_trip(udp_packet(
        CLIENT,
        MDNS_GROUP,
        MDNS_PORT,
        MDNS_PORT,
        dns(MDNS_QU_QUERY),
    ));
    let query = query.packet.get::<Dns>().unwrap();
    assert_eq!(query.id, 0);
    assert!(!query.response);
    assert_eq!(query.questions[0].class, 0x8001);

    let response = round_trip(udp_packet(
        RESPONDER,
        MDNS_GROUP,
        MDNS_PORT,
        MDNS_PORT,
        dns(MDNS_RESPONSE),
    ));
    let response = response.packet.get::<Dns>().unwrap();
    assert_eq!(response.id, 0);
    assert!(response.response && response.authoritative_answer);
    assert_eq!(response.answers[0].class, 0x8001);
    // the cache-flush bit stays in the class and the rdata is still typed
    assert_eq!(
        response.answers[0].value,
        RecordValue::A(Ipv4Addr::new(192, 0, 2, 80))
    );

    // a unicast response comes from 5353 to the querier's port
    let unicast = round_trip(udp_packet(
        RESPONDER,
        CLIENT,
        MDNS_PORT,
        50_000,
        dns(MDNS_RESPONSE),
    ));
    assert_eq!(unicast.packet.get::<Dns>().unwrap().answers.len(), 1);
}

#[test]
fn the_cache_flush_class_is_masked_only_on_the_mdns_port() {
    // Only transport dispatch from UDP port 5353 reads the top record-class
    // bit as RFC 6762's cache-flush flag. Unicast DNS and LLMNR (RFC 4795,
    // which defines no such flag) keep class 0x8001 unknown.
    let address = Ipv4Addr::new(192, 0, 2, 80);
    for (ports, typed) in [
        ((MDNS_PORT, MDNS_PORT), true),
        ((MDNS_PORT, 50_000), true),
        ((53, 50_000), false),
        ((50_000, 53), false),
        ((LLMNR_PORT, 50_000), false),
    ] {
        let decoded = dissect(
            build_with(
                udp_packet(RESPONDER, CLIENT, ports.0, ports.1, dns(MDNS_RESPONSE)),
                codec::Mode::Strict,
            )
            .bytes,
        );
        let answer = &decoded.packet.get::<Dns>().unwrap().answers[0];
        assert_eq!(answer.class, 0x8001, "{ports:?}");
        if typed {
            assert_eq!(answer.value, RecordValue::A(address), "{ports:?}");
        } else {
            assert!(
                matches!(&answer.value, RecordValue::Unknown { type_code: 1, .. }),
                "{ports:?}: {:?}",
                answer.value
            );
        }
    }
}

#[test]
fn llmnr_queries_decode_as_dns() {
    let decoded = round_trip(udp_packet(
        CLIENT,
        [224, 0, 0, 252],
        50_000,
        LLMNR_PORT,
        dns(LLMNR_QUERY),
    ));
    let query = decoded.packet.get::<Dns>().unwrap();
    assert_eq!(query.id, 0x1234);
    assert_eq!(query.questions[0].name.to_string(), "host.");
    // and the response, from 5355 back to the querier
    let response = round_trip(udp_packet(
        RESPONDER,
        CLIENT,
        LLMNR_PORT,
        50_000,
        dns(b"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x00\x00\x01\x00\x01"),
    ));
    assert!(response.packet.get::<Dns>().unwrap().response);
}

#[test]
fn malformed_dns_on_the_multicast_ports_keeps_its_bytes() {
    for port in [MDNS_PORT, LLMNR_PORT] {
        let wire = build_with(
            udp_packet(
                CLIENT,
                MDNS_GROUP,
                50_000,
                port,
                Raw::new(vec![0x12, 0x34, 0x81]),
            ),
            codec::Mode::Permissive,
        )
        .bytes;
        let decoded = dissect(wire.clone());
        assert_eq!(protocols(&decoded), ["ipv4", "udp", "malformed"], "{port}");
        let malformed = decoded.packet.get::<Malformed>().unwrap();
        assert_eq!(malformed.intended_protocol.as_deref(), Some("dns"));
        assert_eq!(malformed.bytes.as_ref(), [0x12, 0x34, 0x81]);
    }
}

#[test]
fn port_53_decoding_is_unchanged_beside_the_new_bindings() {
    let decoded = round_trip(udp_packet(CLIENT, RESPONDER, 50_000, 53, dns(LLMNR_QUERY)));
    assert_eq!(decoded.packet.get::<Dns>().unwrap().id, 0x1234);
    // a response to a port that is itself registered decodes by the source port
    let response = round_trip(udp_packet(
        RESPONDER,
        CLIENT,
        53,
        MDNS_PORT,
        dns(b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x00\x00\x01\x00\x01"),
    ));
    assert!(response.packet.get::<Dns>().unwrap().response);
}

fn decoded_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    wire: &[u8],
) -> Packet {
    dissect(
        build_with(
            udp_packet(
                source,
                destination,
                source_port,
                destination_port,
                dns(wire),
            ),
            codec::Mode::Strict,
        )
        .bytes,
    )
    .packet
}

#[test]
fn multicast_queries_pair_only_as_the_existing_matcher_rules_allow() {
    let registry = registry();
    let matcher = registry.matcher("dns").expect("DNS matcher");
    let multicast_query = decoded_packet(CLIENT, MDNS_GROUP, MDNS_PORT, MDNS_PORT, MDNS_QU_QUERY);

    // an mDNS answer to the group comes from another address and carries no
    // question to echo, so it is not attributed to the query
    let group_response = decoded_packet(RESPONDER, MDNS_GROUP, MDNS_PORT, MDNS_PORT, MDNS_RESPONSE);
    assert!(matcher.matches(&multicast_query, &group_response).is_none());
    // a unicast reply from a source other than the multicast destination
    // does not reverse the query's endpoints either
    let unicast_response = decoded_packet(RESPONDER, CLIENT, MDNS_PORT, MDNS_PORT, MDNS_RESPONSE);
    assert!(
        matcher
            .matches(&multicast_query, &unicast_response)
            .is_none()
    );

    // a legacy unicast query (RFC 6762 section 6.7) is answered by its
    // addressee with the transaction id and question echoed, id 0 included
    for id in [0_u16, 0x2222] {
        let mut query = MDNS_QU_QUERY.to_vec();
        query[..2].copy_from_slice(&id.to_be_bytes());
        let mut reply = MDNS_RESPONSE[..12].to_vec();
        reply[..2].copy_from_slice(&id.to_be_bytes());
        reply[4..6].copy_from_slice(&1_u16.to_be_bytes());
        reply.extend_from_slice(&MDNS_QU_QUERY[12..]);
        reply.extend_from_slice(&MDNS_RESPONSE[12..]);
        let request = decoded_packet(CLIENT, RESPONDER, 50_000, MDNS_PORT, &query);
        let response = decoded_packet(RESPONDER, CLIENT, MDNS_PORT, 50_000, &reply);
        let matched = matcher
            .matches(&request, &response)
            .unwrap_or_else(|| panic!("id {id} pairs"));
        assert_eq!(matched.confidence, 250);
        assert_eq!(
            matcher.responder(&request, &response),
            Some(std::net::IpAddr::V4(Ipv4Addr::from(RESPONDER)))
        );
    }

    // an id-0 response does not answer a query that carries another id
    let mut query = MDNS_QU_QUERY.to_vec();
    query[..2].copy_from_slice(&0x2222_u16.to_be_bytes());
    let mut reply = MDNS_RESPONSE[..12].to_vec();
    reply[4..6].copy_from_slice(&1_u16.to_be_bytes());
    reply.extend_from_slice(&MDNS_QU_QUERY[12..]);
    reply.extend_from_slice(&MDNS_RESPONSE[12..]);
    let request = decoded_packet(CLIENT, RESPONDER, 50_000, MDNS_PORT, &query);
    let response = decoded_packet(RESPONDER, CLIENT, MDNS_PORT, 50_000, &reply);
    assert!(matcher.matches(&request, &response).is_none());
}
