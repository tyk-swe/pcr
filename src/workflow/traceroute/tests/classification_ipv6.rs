use std::net::Ipv6Addr;

use super::super::engine::traceroute_identity;
use super::super::*;
use super::support::decoded_at;
use crate::protocol::builtin::registry as default_registry;
use crate::protocol::ipv6::SegmentRoutingHeader;

#[test]
fn ipv6_classifier_accepts_intermediate_response() {
    let registry = default_registry().unwrap();
    let local6: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
    let router6: Ipv6Addr = "fd00::fe".parse().unwrap();
    let mut udp_probe_packet = TracerouteProbe {
        sequence: 9,
        address: IpAddr::V6(remote6),
        strategy: TracerouteStrategy::Udp,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT + 9),
        hop_limit: 4,
        attempt: 1,
    }
    .packet();
    udp_probe_packet.get_mut::<Ipv6>().unwrap().source = local6;
    let intermediate6 = icmpv6_error(router6, local6, 3, 0, ipv6_udp_quote(&udp_probe_packet), 11);
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &udp_probe_packet,
            &intermediate6,
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::Intermediate
    );
}

#[test]
fn tunneled_direct_reply_reaches_the_inner_destination() {
    let registry = default_registry().unwrap();
    let outer_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let inner_source: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
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
            source_port: TRACEROUTE_SOURCE_PORT,
            destination_port: DEFAULT_TRACEROUTE_UDP_PORT,
            ..Udp::default()
        });
    let mut reply = Packet::new();
    reply
        .push(Ipv6 {
            source: "2001:db8:ffff::1".parse().unwrap(),
            destination: "2001:db8:ffff::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_destination,
            destination: inner_source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: DEFAULT_TRACEROUTE_UDP_PORT,
            destination_port: TRACEROUTE_SOURCE_PORT,
            ..Udp::default()
        });

    let classification = classify_traceroute_response(
        &registry,
        TracerouteStrategy::Udp,
        &request,
        &decoded_at(reply, 2, Vec::new()),
    )
    .unwrap();

    assert_eq!(
        classification.kind,
        TracerouteResponseKind::DestinationReached
    );
    assert_eq!(classification.responder, IpAddr::V6(inner_destination));
}

#[test]
fn srh_direct_reply_reaches_the_final_destination() {
    let registry = default_registry().unwrap();
    let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let active: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source,
            destination: active,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![active, final_destination],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp {
            source_port: TRACEROUTE_SOURCE_PORT,
            destination_port: DEFAULT_TRACEROUTE_UDP_PORT,
            ..Udp::default()
        });
    let mut reply = Packet::new();
    reply
        .push(Ipv6 {
            source: final_destination,
            destination: source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: DEFAULT_TRACEROUTE_UDP_PORT,
            destination_port: TRACEROUTE_SOURCE_PORT,
            ..Udp::default()
        });

    let classification = classify_traceroute_response(
        &registry,
        TracerouteStrategy::Udp,
        &request,
        &decoded_at(reply, 2, Vec::new()),
    )
    .unwrap();

    assert_eq!(
        classification.kind,
        TracerouteResponseKind::DestinationReached
    );
    assert_eq!(classification.responder, IpAddr::V6(final_destination));
}

#[test]
fn icmp_strategy_builds_hop_limit_and_accepts_direct_terminal_reply() {
    let registry = default_registry().unwrap();
    let local6: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
    let mut echo_request = TracerouteProbe {
        sequence: 23,
        address: IpAddr::V6(remote6),
        strategy: TracerouteStrategy::Icmp,
        destination_port: None,
        hop_limit: 9,
        attempt: 1,
    }
    .packet();
    assert_eq!(echo_request.get::<Ipv6>().unwrap().hop_limit, 9);
    echo_request.get_mut::<Ipv6>().unwrap().source = local6;
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv6 {
            source: remote6,
            destination: local6,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 129,
            body: traceroute_identity(23),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_traceroute_response(
            &registry,
            TracerouteStrategy::Icmp,
            &echo_request,
            &decoded_at(echo_reply, 2, Vec::new()),
        )
        .unwrap()
        .kind,
        TracerouteResponseKind::DestinationReached
    );
}

fn ipv6_udp_quote(packet: &Packet) -> Vec<u8> {
    let ip = packet.get::<Ipv6>().unwrap();
    let udp = packet.get::<Udp>().unwrap();
    let mut quote = vec![0_u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
    quote[6] = 17;
    quote[7] = ip.hop_limit;
    quote[8..24].copy_from_slice(&ip.source.octets());
    quote[24..40].copy_from_slice(&ip.destination.octets());
    quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
    quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
    quote[44..46].copy_from_slice(&8_u16.to_be_bytes());
    quote
}

fn icmpv6_error(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
    seconds: u64,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    decoded_at(packet, seconds, Vec::new())
}
