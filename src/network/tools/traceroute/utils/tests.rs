// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use anyhow::Result;
use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::MutablePacket;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

struct TestReceiver {
    responses: VecDeque<Option<(Vec<u8>, IpAddr)>>,
}

impl TestReceiver {
    fn new(responses: VecDeque<Option<(Vec<u8>, IpAddr)>>) -> Self {
        Self { responses }
    }
}

impl PacketReceiver for TestReceiver {
    fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
        Ok(self.responses.pop_front().unwrap_or(None))
    }
}

fn build_icmpv4_udp_reply(
    dest_port: u16,
    payload: [u8; 4],
    code: pnet::packet::icmp::IcmpCode,
) -> Vec<u8> {
    let udp_len = UdpPacket::minimum_packet_size() + payload.len();
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
        udp.set_source(1234);
        udp.set_destination(dest_port);
        udp.set_length(udp_len as u16);
        udp.set_payload(&payload);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_icmp_code(code);
        icmp.set_payload(&ipv4_bytes);
    }
    icmp_bytes
}

fn build_custom_icmpv4_packet(
    dest_port: u16,
    payload: &[u8],
    icmp_type: pnet::packet::icmp::IcmpType,
    icmp_code: pnet::packet::icmp::IcmpCode,
    next_level_protocol: IpNextHeaderProtocol,
) -> Vec<u8> {
    let transport_len = if next_level_protocol == IpNextHeaderProtocols::Udp {
        UdpPacket::minimum_packet_size() + payload.len()
    } else {
        // For simplicity, just use length of payload for non-UDP
        payload.len()
    };

    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + transport_len];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(next_level_protocol);

        if next_level_protocol == IpNextHeaderProtocols::Udp {
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(dest_port);
            udp.set_length(transport_len as u16);
            udp.set_payload(payload);
        } else {
            ipv4.set_payload(payload);
        }
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(icmp_type);
        icmp.set_icmp_code(icmp_code);
        icmp.set_payload(&ipv4_bytes);
    }
    icmp_bytes
}

fn build_icmpv4_tcp_reply(source_port: u16, dest_port: u16) -> Vec<u8> {
    let tcp_len = TcpPacket::minimum_packet_size();
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + tcp_len];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).expect("tcp packet");
        tcp.set_source(source_port);
        tcp.set_destination(dest_port);
        tcp.set_data_offset(5);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
        icmp.set_payload(&ipv4_bytes);
    }
    icmp_bytes
}

#[test]
fn classify_icmp_event_v4_returns_destination_when_port_unreachable() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::DestinationUnreachable,
        IcmpDestinationUnreachableCodes::DestinationPortUnreachable,
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Destination)));
}

#[test]
fn classify_icmp_event_v4_returns_hop_when_other_unreachable() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::DestinationUnreachable,
        IcmpDestinationUnreachableCodes::DestinationHostUnreachable,
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Hop)));
}

#[test]
fn classify_icmp_event_v4_returns_hop_when_time_exceeded() {
    let dest_port = 33434;
    let payload = [2, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((2, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Hop)));
}

#[test]
fn classify_icmp_event_v4_returns_none_when_protocol_mismatch() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    // Inner packet uses TCP, but we expect UDP
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Tcp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v4_returns_none_when_port_mismatch() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port + 1, // Mismatched port
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v4_with_source_returns_none_when_source_port_mismatch() {
    let source_port = 40_000;
    let dest_port = 80;
    let packet_bytes = build_icmpv4_tcp_reply(source_port, dest_port);
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result = classify_icmp_event_v4_with_source(
        &packet,
        IpNextHeaderProtocols::Tcp,
        Some(source_port + 1),
        dest_port,
        None,
    );

    assert!(result.is_none());
    assert!(matches!(
        classify_icmp_event_v4_with_source(
            &packet,
            IpNextHeaderProtocols::Tcp,
            Some(source_port),
            dest_port,
            None
        ),
        Some(IcmpEventKind::Hop)
    ));
}

#[test]
fn classify_icmp_event_v4_returns_none_when_ttl_mismatch() {
    let dest_port = 33434;
    let payload = [2, 1, 0xBE, 0xEF]; // TTL=2 in payload
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    // We expect TTL=1
    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v4_returns_none_when_probe_mismatch() {
    let dest_port = 33434;
    let payload = [1, 2, 0xBE, 0xEF]; // Probe=2 in payload
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    // We expect Probe=1
    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v4_returns_none_when_magic_mismatch() {
    let dest_port = 33434;
    let payload = [1, 1, 0xDE, 0xAD]; // Wrong magic bytes
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    let result =
        classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v4_succeeds_without_verification_params() {
    let dest_port = 33434;
    let payload = [0, 0, 0, 0]; // Random payload
    let packet_bytes = build_custom_icmpv4_packet(
        dest_port,
        &payload,
        IcmpTypes::TimeExceeded,
        pnet::packet::icmp::IcmpCode::new(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = IcmpPacket::new(&packet_bytes).expect("icmp packet");

    // No verification params provided
    let result = classify_icmp_event_v4(&packet, IpNextHeaderProtocols::Udp, dest_port, None);

    assert!(matches!(result, Some(IcmpEventKind::Hop)));
}

fn build_custom_icmpv6_packet(
    dest_port: u16,
    payload: &[u8],
    icmp_type: pnet::packet::icmpv6::Icmpv6Type,
    icmp_code: pnet::packet::icmpv6::Icmpv6Code,
    next_header: IpNextHeaderProtocol,
) -> Vec<u8> {
    let transport_len = if next_header == IpNextHeaderProtocols::Udp {
        UdpPacket::minimum_packet_size() + payload.len()
    } else {
        payload.len()
    };

    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + transport_len];
    let ipv6_payload_len = transport_len as u16;
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(ipv6_payload_len);
        ipv6.set_next_header(next_header);

        if next_header == IpNextHeaderProtocols::Udp {
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(dest_port);
            udp.set_length(transport_len as u16);
            udp.set_payload(payload);
        } else {
            ipv6.set_payload(payload);
        }
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(icmp_type);
        icmp.set_icmpv6_code(icmp_code);
        icmp.set_payload(&ipv6_bytes);
    }
    icmp_bytes
}

fn build_icmpv6_tcp_reply(source_port: u16, dest_port: u16) -> Vec<u8> {
    let tcp_len = TcpPacket::minimum_packet_size();
    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + tcp_len];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(tcp_len as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Tcp);

        let mut tcp = MutableTcpPacket::new(ipv6.payload_mut()).expect("tcp packet");
        tcp.set_source(source_port);
        tcp.set_destination(dest_port);
        tcp.set_data_offset(5);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        icmp.set_icmpv6_code(Icmpv6Code(0));
        icmp.set_payload(&ipv6_bytes);
    }
    icmp_bytes
}

#[test]
fn classify_icmp_event_v6_returns_destination_when_port_unreachable() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::DestinationUnreachable,
        Icmpv6Code(ICMPV6_PORT_UNREACHABLE_CODE),
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Destination)));
}

#[test]
fn classify_icmp_event_v6_returns_hop_when_other_unreachable() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::DestinationUnreachable,
        Icmpv6Code(0), // No route to destination
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Hop)));
}

#[test]
fn classify_icmp_event_v6_returns_hop_when_time_exceeded() {
    let dest_port = 33434;
    let payload = [2, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::TimeExceeded,
        Icmpv6Code(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((2, 1)));

    assert!(matches!(result, Some(IcmpEventKind::Hop)));
}

#[test]
fn classify_icmp_event_v6_returns_none_when_protocol_mismatch() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::TimeExceeded,
        Icmpv6Code(0),
        IpNextHeaderProtocols::Tcp, // Mismatched protocol
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v6_returns_none_when_port_mismatch() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port + 1, // Mismatched port
        &payload,
        Icmpv6Types::TimeExceeded,
        Icmpv6Code(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v6_with_source_returns_none_when_source_port_mismatch() {
    let source_port = 40_000;
    let dest_port = 80;
    let packet_bytes = build_icmpv6_tcp_reply(source_port, dest_port);
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result = classify_icmp_event_v6_with_source(
        &packet,
        IpNextHeaderProtocols::Tcp,
        Some(source_port + 1),
        dest_port,
        None,
    );

    assert!(result.is_none());
    assert!(matches!(
        classify_icmp_event_v6_with_source(
            &packet,
            IpNextHeaderProtocols::Tcp,
            Some(source_port),
            dest_port,
            None
        ),
        Some(IcmpEventKind::Hop)
    ));
}

#[test]
fn classify_icmp_event_v6_returns_none_when_verification_mismatch() {
    let dest_port = 33434;
    let payload = [99, 99, 0xBE, 0xEF]; // Wrong TTL/Probe
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::TimeExceeded,
        Icmpv6Code(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result =
        classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, Some((1, 1)));

    assert!(result.is_none());
}

#[test]
fn classify_icmp_event_v6_succeeds_without_verification_params() {
    let dest_port = 33434;
    let payload = [1, 1, 0xBE, 0xEF];
    let packet_bytes = build_custom_icmpv6_packet(
        dest_port,
        &payload,
        Icmpv6Types::TimeExceeded,
        Icmpv6Code(0),
        IpNextHeaderProtocols::Udp,
    );
    let packet = Icmpv6Packet::new(&packet_bytes).expect("icmpv6 packet");

    let result = classify_icmp_event_v6(&packet, IpNextHeaderProtocols::Udp, dest_port, None);

    assert!(result.is_some());
}

#[test]
fn run_probe_loop_returns_destination_event() {
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut calls = 0;
    let result = run_probe_loop(Duration::from_millis(50), |_: Duration| {
        calls += 1;
        if calls == 1 {
            Ok(Some(ProbeEvent::Destination(addr)))
        } else {
            Ok(None)
        }
    })
    .expect("probe loop result");

    match result {
        ProbeResult::Destination(got, elapsed) => {
            assert_eq!(got, addr);
            assert!(elapsed < 1000);
        }
        _ => panic!("expected destination result"),
    }
}

#[test]
fn run_probe_loop_times_out_without_events() {
    let result =
        run_probe_loop(Duration::from_millis(5), |_slice| Ok(None)).expect("probe loop result");
    assert!(matches!(result, ProbeResult::Timeout));
}

#[test]
fn await_icmp_response_v4_reports_destination() {
    let dest_port = 33437;
    let payload = [1, 0, 0xBE, 0xEF];
    let packet = build_icmpv4_udp_reply(
        dest_port,
        payload,
        IcmpDestinationUnreachableCodes::DestinationPortUnreachable,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let mut receiver = TestReceiver::new(VecDeque::from(vec![Some((packet, addr))]));

    let result = await_icmp_response_v4(
        &mut receiver,
        IpNextHeaderProtocols::Udp,
        dest_port,
        Some((1, 0)),
        Duration::from_millis(20),
    )
    .expect("await result");

    match result {
        ProbeResult::Destination(got, _) => assert_eq!(got, addr),
        _ => panic!("expected destination result"),
    }
}

#[test]
fn await_icmp_response_v4_reports_hop() {
    let dest_port = 33440;
    let payload = [2, 1, 0xBE, 0xEF];
    let packet = build_icmpv4_udp_reply(
        dest_port,
        payload,
        IcmpDestinationUnreachableCodes::DestinationHostUnreachable,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let mut receiver = TestReceiver::new(VecDeque::from(vec![Some((packet, addr))]));

    let result = await_icmp_response_v4(
        &mut receiver,
        IpNextHeaderProtocols::Udp,
        dest_port,
        Some((2, 1)),
        Duration::from_millis(20),
    )
    .expect("await result");

    match result {
        ProbeResult::Hop(got, _) => assert_eq!(got, addr),
        _ => panic!("expected hop result"),
    }
}

#[test]
fn build_echo_request_success() {
    let mut buffer = vec![0u8; MutableEchoRequestPacket::minimum_packet_size()];
    let identifier = 0x1234;
    let sequence = 0x5678;

    build_echo_request(&mut buffer, identifier, sequence).expect("build failed");

    let packet = EchoRequestPacket::new(&buffer).expect("parse packet");
    assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
    assert_eq!(packet.get_identifier(), identifier);
    assert_eq!(packet.get_sequence_number(), sequence);
    // Verify checksum was calculated (should be non-zero for these values)
    assert_ne!(packet.get_checksum(), 0);
}

#[test]
fn build_echo_request_buffer_too_small() {
    let mut buffer = vec![0u8; MutableEchoRequestPacket::minimum_packet_size() - 1];
    let identifier = 0x1234;
    let sequence = 0x5678;

    let result = build_echo_request(&mut buffer, identifier, sequence);
    assert!(result.is_err());
}
