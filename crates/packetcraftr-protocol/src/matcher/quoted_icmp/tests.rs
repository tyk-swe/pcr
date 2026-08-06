// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;

use crate::{
    gre::Gre,
    icmp::{Icmpv4, Icmpv6},
    ipv6::{DestinationOptions, HopByHop},
    link::Ethernet,
    network::{Ipv4, Ipv6},
    transport::{Sctp, Tcp, Udp},
    tunnel::Vxlan,
};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    field::WireValue,
    matcher::ResponseMatcher,
    semantics::BuiltinProtocol,
};

use super::super::{
    EchoMatcher, QuotedProbeTransport, ReverseFlowMatcher, quoted_icmp_error_kind,
    tests::{
        MalformedIpv4, echo, quoted_icmpv4_time_exceeded, quoted_icmpv6_time_exceeded, sctp_init,
    },
};

#[test]
fn matchers_accept_quoted_icmp_errors_for_each_probe_transport() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut udp = Packet::new();
    udp.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    })
    .push(Udp {
        source_port: 12_345,
        destination_port: 33_434,
        ..Udp::default()
    });
    let mut tcp = Packet::new();
    tcp.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    })
    .push(Tcp {
        source_port: 12_345,
        destination_port: 443,
        sequence: 17,
        flags: Tcp::SYN,
        ..Tcp::default()
    });
    let icmp = echo(source, destination, 8);
    let sctp = sctp_init(source, destination, 0x1122_3344);

    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Udp)
            .matches(&udp, &quoted_icmpv4_time_exceeded(router, source, 17, &udp))
            .matched
    );
    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Tcp)
            .matches(&tcp, &quoted_icmpv4_time_exceeded(router, source, 6, &tcp))
            .matched
    );
    assert!(
        EchoMatcher::v4()
            .matches(
                &icmp,
                &quoted_icmpv4_time_exceeded(router, source, 1, &icmp)
            )
            .matched
    );
    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(
                &sctp,
                &quoted_icmpv4_time_exceeded(router, source, 132, &sctp)
            )
            .matched
    );
}

#[test]
fn quoted_icmp_errors_require_matching_transport_and_inner_payload_lengths() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut request = Packet::new();
    request
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 33_434,
            ..Udp::default()
        });
    let valid = quoted_icmpv4_time_exceeded(router, source, 17, &request);
    assert!(quoted_icmp_error_kind(&request, &valid, QuotedProbeTransport::Udp).is_some());
    assert!(quoted_icmp_error_kind(&request, &valid, QuotedProbeTransport::Tcp).is_none());

    let mut malformed_v4 = valid;
    let mut body = malformed_v4.get::<Icmpv4>().unwrap().body.to_vec();
    body[6..8].copy_from_slice(&0_u16.to_be_bytes());
    malformed_v4.get_mut::<Icmpv4>().unwrap().body = Bytes::from(body);
    assert!(quoted_icmp_error_kind(&request, &malformed_v4, QuotedProbeTransport::Udp).is_none());

    let source_v6: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination_v6: Ipv6Addr = "fd00::2".parse().unwrap();
    let router_v6: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut request_v6 = Packet::new();
    request_v6
        .push(Ipv6 {
            source: source_v6,
            destination: destination_v6,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 33_434,
            ..Udp::default()
        });
    let valid_v6 = quoted_icmpv6_time_exceeded(router_v6, source_v6, &request_v6);
    assert!(quoted_icmp_error_kind(&request_v6, &valid_v6, QuotedProbeTransport::Udp).is_some());
    let mut malformed_v6 = valid_v6;
    let mut body = malformed_v6.get::<Icmpv6>().unwrap().body.to_vec();
    body[8..10].copy_from_slice(&0_u16.to_be_bytes());
    malformed_v6.get_mut::<Icmpv6>().unwrap().body = Bytes::from(body);
    assert!(
        quoted_icmp_error_kind(&request_v6, &malformed_v6, QuotedProbeTransport::Udp).is_none()
    );
}

#[test]
fn sctp_quoted_icmp_requires_enough_bytes_to_identify_the_init() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let request = sctp_init(source, destination, 0x1122_3344);
    let same_tuple = sctp_init(source, destination, 0x5566_7788);
    let response = quoted_icmpv4_time_exceeded(router, source, 132, &request);

    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&request, &response)
            .matched
    );
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&same_tuple, &response)
            .matched
    );

    let mut short = response;
    let body = short.get_mut::<Icmpv4>().unwrap();
    body.body = body.body.slice(..32);
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&request, &short)
            .matched
    );
}

#[test]
fn sctp_quoted_icmp_matches_a_permissively_built_raw_checksum() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut request = sctp_init(source, destination, 0x1122_3344);
    request.get_mut::<Sctp>().unwrap().checksum =
        WireValue::Raw(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));
    let registry = Arc::new(crate::builtin::registry().unwrap());
    let built = Builder::new(registry)
        .build(
            request,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    let response = quoted_icmpv4_time_exceeded(router, source, 132, &built.packet);

    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Sctp)
            .matches(&built.packet, &response)
            .matched
    );
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

#[test]
fn tunneled_or_ip_in_ip_icmp_errors_are_not_direct_responses() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let mut request = Packet::new();
    request
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 33_434,
            ..Udp::default()
        });
    let direct = quoted_icmpv4_time_exceeded(router, source, 17, &request);
    let quoted_error = direct.get::<Icmpv4>().unwrap().clone();

    let mut tunneled = Packet::new();
    tunneled
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 200),
            destination: source,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 4789,
            destination_port: 40_000,
            ..Udp::default()
        })
        .push(Vxlan::default())
        .push(Ethernet::default())
        .push(Ipv4 {
            source: router,
            destination: source,
            ..Ipv4::default()
        })
        .push(quoted_error.clone());
    assert!(quoted_icmp_error_kind(&request, &tunneled, QuotedProbeTransport::Udp).is_none());
    assert!(
        !ReverseFlowMatcher::new(BuiltinProtocol::Udp)
            .matches(&request, &tunneled)
            .matched
    );

    let mut gre = Packet::new();
    gre.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 200),
        destination: source,
        ..Ipv4::default()
    })
    .push(Gre::default())
    .push(Ipv4 {
        source: router,
        destination: source,
        ..Ipv4::default()
    })
    .push(quoted_error.clone());
    assert!(quoted_icmp_error_kind(&request, &gre, QuotedProbeTransport::Udp).is_none());

    let mut transport_wrapped = Packet::new();
    transport_wrapped
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 200),
            destination: source,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 40_001,
            ..Udp::default()
        })
        .push(quoted_error.clone());
    assert!(
        quoted_icmp_error_kind(&request, &transport_wrapped, QuotedProbeTransport::Udp).is_none()
    );

    let mut ip_in_ip = Packet::new();
    ip_in_ip
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 200),
            destination: source,
            ..Ipv4::default()
        })
        .push(Ipv4 {
            source: router,
            destination: source,
            ..Ipv4::default()
        })
        .push(quoted_error);
    assert!(quoted_icmp_error_kind(&request, &ip_in_ip, QuotedProbeTransport::Udp).is_none());
}

#[test]
fn quoted_icmpv6_walks_extension_headers_and_rejects_nonfirst_fragments() {
    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        })
        .push(HopByHop::default())
        .push(DestinationOptions::default())
        .push(Udp {
            source_port: 12_345,
            destination_port: 33_434,
            ..Udp::default()
        });

    let mut quote = vec![0_u8; 64];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&24_u16.to_be_bytes());
    quote[6] = 0;
    quote[8..24].copy_from_slice(&source.octets());
    quote[24..40].copy_from_slice(&destination.octets());
    quote[40] = 60;
    quote[41] = 0;
    quote[48] = 17;
    quote[49] = 0;
    quote[56..58].copy_from_slice(&12_345_u16.to_be_bytes());
    quote[58..60].copy_from_slice(&33_434_u16.to_be_bytes());
    let mut body = vec![0_u8; 4];
    body.extend_from_slice(&quote);
    let mut response = Packet::new();
    response
        .push(Ipv6 {
            source: router,
            destination: source,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 3,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    assert!(quoted_icmp_error_kind(&request, &response, QuotedProbeTransport::Udp).is_some());
    assert!(
        ReverseFlowMatcher::new(BuiltinProtocol::Udp)
            .matches(&request, &response)
            .matched
    );

    let mut nonfirst_quote = vec![0_u8; 56];
    nonfirst_quote[0] = 0x60;
    nonfirst_quote[4..6].copy_from_slice(&16_u16.to_be_bytes());
    nonfirst_quote[6] = 44;
    nonfirst_quote[8..24].copy_from_slice(&source.octets());
    nonfirst_quote[24..40].copy_from_slice(&destination.octets());
    nonfirst_quote[40] = 17;
    nonfirst_quote[42..44].copy_from_slice(&8_u16.to_be_bytes());
    nonfirst_quote[48..50].copy_from_slice(&12_345_u16.to_be_bytes());
    nonfirst_quote[50..52].copy_from_slice(&33_434_u16.to_be_bytes());
    let mut body = vec![0_u8; 4];
    body.extend_from_slice(&nonfirst_quote);
    response.get_mut::<Icmpv6>().unwrap().body = Bytes::from(body);
    assert!(quoted_icmp_error_kind(&request, &response, QuotedProbeTransport::Udp).is_none());
}
