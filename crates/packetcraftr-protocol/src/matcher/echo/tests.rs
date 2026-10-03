// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use bytes::Bytes;
use packetcraftr_packet::{Packet, matcher::ResponseMatcher};

use crate::{builtin, icmp::Icmpv6};

use super::super::EchoMatcher;
use super::super::tests::echo;

#[test]
fn icmpv4_echo_matcher_rejects_packets_without_ip_envelopes() {
    let registry = builtin::registry().unwrap();
    let matcher = registry.matcher("icmpv4").unwrap();
    let mut request = echo(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 8);
    let mut response = echo(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 0);
    request.remove(0).unwrap();
    response.remove(0).unwrap();

    assert!(!matcher.matches(&request, &response).matched);
}

#[test]
fn icmpv6_echo_matcher_rejects_packets_without_ip_envelopes() {
    let registry = builtin::registry().unwrap();
    let matcher = registry.matcher("icmpv6").unwrap();
    let mut request = Packet::new();
    request.push(Icmpv6 {
        icmp_type: 128,
        body: Bytes::from_static(&[0x12, 0x34, 0, 7]),
        ..Icmpv6::default()
    });
    let mut response = Packet::new();
    response.push(Icmpv6 {
        icmp_type: 129,
        body: Bytes::from_static(&[0x12, 0x34, 0, 7]),
        ..Icmpv6::default()
    });

    assert!(!matcher.matches(&request, &response).matched);
}

#[test]
fn echo_matcher_requires_reversed_network_endpoints() {
    let request = echo(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 8);
    let unrelated = echo(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 1), 0);
    let response = echo(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 0);

    assert!(!EchoMatcher::v4().matches(&request, &unrelated).matched);
    assert!(EchoMatcher::v4().matches(&request, &response).matched);
}
