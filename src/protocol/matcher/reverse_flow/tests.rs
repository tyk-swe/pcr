// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::packet::{
    Packet, field::FieldValue, layer::Raw, matcher::ResponseMatcher, semantics::BuiltinProtocol,
};
use crate::protocol::{
    ipv6::SegmentRoutingHeader,
    network::Ipv6,
    transport::{Tcp, Udp},
};

use super::super::ReverseFlowMatcher;
use super::super::tests::{address, reflective_udp_packet, sctp_init, sctp_init_ack, tcp_packet};

#[test]
fn sctp_init_matcher_requires_reversed_tuple_and_initiate_tag() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let request = sctp_init(source, destination, 0x1122_3344);
    let response = sctp_init_ack(destination, source, 0x1122_3344, 0x5566_7788);
    let wrong_tag = sctp_init_ack(destination, source, 0x0102_0304, 0x5566_7788);
    let wrong_endpoint =
        sctp_init_ack(Ipv4Addr::new(10, 0, 0, 3), source, 0x1122_3344, 0x5566_7788);

    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&request, &response)
            .matched
    );
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&request, &wrong_tag)
            .matched
    );
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&request, &wrong_endpoint)
            .matched
    );
    assert_eq!(
        ReverseFlowMatcher::new(BuiltinProtocol::Sctp).responder(&request, &response),
        Some(IpAddr::V4(destination))
    );
}

#[test]
fn reverse_tuple_uses_srh_final_destination() {
    let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let first: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source,
            destination: first,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![first, final_destination],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp {
            source_port: 12345,
            destination_port: 9,
            ..Udp::default()
        });
    let mut response = Packet::new();
    response
        .push(Ipv6 {
            source: final_destination,
            destination: source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 9,
            destination_port: 12345,
            ..Udp::default()
        });

    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Udp);
    assert!(matcher.matches(&request, &response).matched);
    assert_eq!(
        matcher.responder(&request, &response),
        Some(IpAddr::V6(final_destination))
    );
}

#[test]
fn reverse_tuple_uses_network_envelope_nearest_transport() {
    let outer_source = address("2001:db8::1");
    let outer_destination = address("2001:db8::2");
    let inner_source = address("2001:db8:1::1");
    let inner_destination = address("2001:db8:1::2");
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 9,
            ..Udp::default()
        });
    let mut response = Packet::new();
    response
        // The outer tunnel endpoints are deliberately unrelated. The
        // UDP response belongs to the encapsulated network envelope.
        .push(Ipv6 {
            source: address("2001:db8:ffff::1"),
            destination: address("2001:db8:ffff::2"),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_destination,
            destination: inner_source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 9,
            destination_port: 12_345,
            ..Udp::default()
        });

    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Udp);
    assert!(matcher.matches(&request, &response).matched);
    assert_eq!(
        matcher.responder(&request, &response),
        Some(IpAddr::V6(inner_destination))
    );
}

#[test]
fn tcp_matcher_uses_acknowledgment_and_rst_sequence_state() {
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);
    let request = tcp_packet(client, server, 100, 0, Tcp::SYN);
    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Tcp);

    let valid_syn_ack = tcp_packet(server, client, 500, 101, Tcp::SYN | Tcp::ACK);
    let wrong_syn_ack = tcp_packet(server, client, 500, 102, Tcp::SYN | Tcp::ACK);
    let valid_ack_rst = tcp_packet(server, client, 0, 101, Tcp::RST | Tcp::ACK);
    let wrong_ack_rst = tcp_packet(server, client, 0, 102, Tcp::RST | Tcp::ACK);
    let valid_bare_rst = tcp_packet(server, client, 0, 0, Tcp::RST);
    let wrong_bare_rst = tcp_packet(server, client, 1, 0, Tcp::RST);

    for response in [valid_syn_ack, valid_ack_rst, valid_bare_rst] {
        assert!(matcher.matches(&request, &response).matched);
    }
    for response in [wrong_syn_ack, wrong_ack_rst, wrong_bare_rst] {
        assert!(!matcher.matches(&request, &response).matched);
    }
}

#[test]
fn tcp_matcher_includes_payload_bytes_in_expected_acknowledgment() {
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);
    let mut request = tcp_packet(client, server, u32::MAX - 2, 0, Tcp::SYN);
    request.push(Raw::new(Bytes::from_static(b"data")));
    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Tcp);

    // Four data bytes plus SYN consume five sequence numbers and wrap.
    let valid = tcp_packet(server, client, 500, 2, Tcp::SYN | Tcp::ACK);
    let payload_omitted = tcp_packet(server, client, 500, u32::MAX - 1, Tcp::SYN | Tcp::ACK);

    assert!(matcher.matches(&request, &valid).matched);
    assert!(!matcher.matches(&request, &payload_omitted).matched);
}

#[test]
fn reordered_same_tuple_tcp_replies_match_only_their_own_probe() {
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);
    let requests =
        [100, 200, 300].map(|sequence| tcp_packet(client, server, sequence, 0, Tcp::SYN));
    let responses = [300, 100, 200]
        .map(|sequence| tcp_packet(server, client, 500, sequence + 1, Tcp::SYN | Tcp::ACK));
    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Tcp);

    for (response, expected_sequence) in responses.iter().zip([300, 100, 200]) {
        let matches = requests
            .iter()
            .enumerate()
            .filter_map(|(index, request)| {
                matcher.matches(request, response).matched.then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(matches, vec![expected_sequence / 100 - 1]);
    }
}

#[test]
fn reverse_matcher_rejects_missing_wrong_and_out_of_range_ports() {
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);
    let matcher = ReverseFlowMatcher::new(BuiltinProtocol::Udp);
    for (request_source, request_destination, response_source, response_destination) in [
        (None, None, None, None),
        (
            Some(FieldValue::Text("12345".to_owned())),
            Some(FieldValue::Unsigned(9)),
            Some(FieldValue::Unsigned(9)),
            Some(FieldValue::Text("12345".to_owned())),
        ),
        (
            Some(FieldValue::Unsigned(u64::from(u16::MAX) + 1)),
            Some(FieldValue::Unsigned(9)),
            Some(FieldValue::Unsigned(9)),
            Some(FieldValue::Unsigned(u64::from(u16::MAX) + 1)),
        ),
    ] {
        let request = reflective_udp_packet(client, server, request_source, request_destination);
        let response = reflective_udp_packet(server, client, response_source, response_destination);
        assert!(!matcher.matches(&request, &response).matched);
    }
}
