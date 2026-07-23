// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use crate::packet::{
    Packet, field::FieldValue, matcher::ResponseMatcher, semantics::BuiltinProtocol,
};
use crate::protocol::{network::Ipv4, transport::Udp};

use super::super::{QuotedProbeTransport, ReverseFlowMatcher, quoted_icmp_error_kind};
use super::support::{MalformedIpv4, quoted_icmpv4_time_exceeded, reflective_udp_packet};

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

#[test]
fn malformed_first_ip_does_not_fall_through_to_an_inner_ip_for_quoted_matching() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut request = Packet::new();
    request
        .push(MalformedIpv4)
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 9,
            ..Udp::default()
        });
    let response = quoted_icmpv4_time_exceeded(router, source, 17, &request);

    assert!(quoted_icmp_error_kind(&request, &response, QuotedProbeTransport::Udp).is_none());
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Udp)
            .matches(&request, &response)
            .matched
    );
}
