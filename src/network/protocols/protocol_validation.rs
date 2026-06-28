// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OriginalTransport {
    pub(crate) protocol: IpNextHeaderProtocol,
    pub(crate) source: u16,
    pub(crate) destination: u16,
    pub(crate) payload: Vec<u8>,
}

impl OriginalTransport {
    pub(crate) fn matches_expected_destination(
        &self,
        expected_protocol: IpNextHeaderProtocol,
        expected_destination: u16,
    ) -> bool {
        self.protocol == expected_protocol && self.destination == expected_destination
    }
}

pub(crate) fn extract_original_transport_v4(packet: &IcmpPacket) -> Option<OriginalTransport> {
    if !matches!(
        packet.get_icmp_type(),
        IcmpTypes::DestinationUnreachable | IcmpTypes::TimeExceeded | IcmpTypes::ParameterProblem
    ) {
        return None;
    }
    let payload = packet.payload();
    if payload.len() < Ipv4Packet::minimum_packet_size() {
        // Guard against truncated IPv4 headers before attempting to parse transport bytes.
        return None;
    }
    let inner = Ipv4Packet::new(payload)?;
    // If the original packet was fragmented, the transport header is only in the first fragment.
    // We cannot parse the payload as a transport header if fragment_offset > 0.
    if inner.get_fragment_offset() > 0 {
        return None;
    }
    let proto = inner.get_next_level_protocol();
    let inner_payload = inner.payload();
    if inner_payload.len() < 4 {
        return None;
    }
    original_transport_from_payload(proto, inner_payload)
}

pub(crate) fn extract_original_transport_v6(packet: &Icmpv6Packet) -> Option<OriginalTransport> {
    if !matches!(
        packet.get_icmpv6_type(),
        Icmpv6Types::DestinationUnreachable
            | Icmpv6Types::PacketTooBig
            | Icmpv6Types::TimeExceeded
            | Icmpv6Types::ParameterProblem
    ) {
        return None;
    }
    let payload = packet.payload();
    if payload.len() < Ipv6Packet::minimum_packet_size() {
        // An incomplete IPv6 header means we cannot trust the embedded transport data.
        return None;
    }
    let inner = Ipv6Packet::new(payload)?;
    let proto = inner.get_next_header();
    let inner_payload = inner.payload();
    if inner_payload.len() < 4 {
        return None;
    }
    original_transport_from_payload(proto, inner_payload)
}

fn original_transport_from_payload(
    proto: IpNextHeaderProtocol,
    inner_payload: &[u8],
) -> Option<OriginalTransport> {
    match proto {
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(inner_payload)?;
            Some(OriginalTransport {
                protocol: proto,
                source: udp.get_source(),
                destination: udp.get_destination(),
                payload: udp.payload().to_vec(),
            })
        }
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(inner_payload)?;
            Some(OriginalTransport {
                protocol: proto,
                source: tcp.get_source(),
                destination: tcp.get_destination(),
                payload: tcp.payload().to_vec(),
            })
        }
        IpNextHeaderProtocols::Sctp => {
            let payload = if inner_payload.len() > 12 {
                inner_payload[12..].to_vec()
            } else {
                Vec::new()
            };
            Some(OriginalTransport {
                protocol: proto,
                source: u16::from_be_bytes([inner_payload[0], inner_payload[1]]),
                destination: u16::from_be_bytes([inner_payload[2], inner_payload[3]]),
                payload,
            })
        }
        _ => None,
    }
}

pub(crate) fn extract_inner_echo_v4(packet: &IcmpPacket) -> Option<(u16, u16)> {
    if !matches!(
        packet.get_icmp_type(),
        IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable | IcmpTypes::ParameterProblem
    ) {
        return None;
    }
    let payload = packet.payload();
    if payload.len() < Ipv4Packet::minimum_packet_size() {
        // ICMP timeouts only carry the first bytes of the original datagram; ensure it is intact.
        return None;
    }
    let inner = Ipv4Packet::new(payload)?;
    let inner_payload = inner.payload();
    if inner_payload.len() < 8 {
        return None;
    }
    let echo = EchoRequestPacket::new(inner_payload)?;
    Some((echo.get_identifier(), echo.get_sequence_number()))
}

pub(crate) fn extract_inner_echo_v6(packet: &Icmpv6Packet) -> Option<(u16, u16)> {
    if !matches!(
        packet.get_icmpv6_type(),
        Icmpv6Types::DestinationUnreachable | Icmpv6Types::PacketTooBig | Icmpv6Types::TimeExceeded
    ) {
        return None;
    }
    let payload = packet.payload();
    if payload.len() < Ipv6Packet::minimum_packet_size() {
        return None;
    }
    let inner = Ipv6Packet::new(payload)?;
    if inner.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }
    let inner_payload = inner.payload();
    if inner_payload.len() < 4 {
        return None;
    }
    let inner_packet = Icmpv6Packet::new(inner_payload)?;
    parse_icmpv6_echo(&inner_packet)
}

pub(crate) fn parse_icmpv6_echo(packet: &Icmpv6Packet) -> Option<(u16, u16)> {
    let payload = packet.payload();
    if payload.len() < 4 {
        return None;
    }
    let identifier = u16::from_be_bytes([payload[0], payload[1]]);
    let sequence = u16::from_be_bytes([payload[2], payload[3]]);
    Some((identifier, sequence))
}

#[cfg(test)]
mod tests;
