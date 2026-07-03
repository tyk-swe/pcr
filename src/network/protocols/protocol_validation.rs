// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(any(feature = "scan", feature = "traceroute"))]
use std::net::IpAddr;

#[cfg(feature = "traceroute")]
use pnet::packet::icmp::echo_request::EchoRequestPacket;
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::icmpv6::Icmpv6Packet;
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::tcp::TcpPacket;
#[cfg(any(feature = "scan", feature = "traceroute"))]
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[cfg(any(feature = "scan", feature = "traceroute"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OriginalTransport {
    pub(crate) protocol: IpNextHeaderProtocol,
    pub(crate) source_ip: IpAddr,
    pub(crate) destination_ip: IpAddr,
    pub(crate) source: u16,
    pub(crate) destination: u16,
    pub(crate) payload: Vec<u8>,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OriginalEcho {
    pub(crate) source_ip: IpAddr,
    pub(crate) destination_ip: IpAddr,
    pub(crate) identifier: u16,
    pub(crate) sequence: u16,
}

pub(crate) struct Ipv6TransportPayload<'a> {
    pub(crate) protocol: IpNextHeaderProtocol,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn ipv6_transport_payload<'a>(
    packet: &'a Ipv6Packet<'a>,
) -> Option<Ipv6TransportPayload<'a>> {
    let mut protocol = packet.get_next_header();
    let mut payload = packet.payload();

    for _ in 0..8 {
        match protocol {
            IpNextHeaderProtocols::Hopopt
            | IpNextHeaderProtocols::Ipv6Route
            | IpNextHeaderProtocols::Ipv6Opts => {
                if payload.len() < 2 {
                    return None;
                }
                let next = IpNextHeaderProtocol::new(payload[0]);
                let header_len = (usize::from(payload[1]) + 1) * 8;
                if payload.len() < header_len {
                    return None;
                }
                protocol = next;
                payload = &payload[header_len..];
            }
            IpNextHeaderProtocols::Ipv6Frag => {
                if payload.len() < 8 {
                    return None;
                }
                let fragment_field = u16::from_be_bytes([payload[2], payload[3]]);
                let fragment_offset = (fragment_field & 0xfff8) >> 3;
                if fragment_offset != 0 {
                    return None;
                }
                protocol = IpNextHeaderProtocol::new(payload[0]);
                payload = &payload[8..];
            }
            IpNextHeaderProtocols::Ah => {
                if payload.len() < 2 {
                    return None;
                }
                let next = IpNextHeaderProtocol::new(payload[0]);
                let header_len = (usize::from(payload[1]) + 2) * 4;
                if payload.len() < header_len {
                    return None;
                }
                protocol = next;
                payload = &payload[header_len..];
            }
            IpNextHeaderProtocols::Ipv6NoNxt => return None,
            _ => return Some(Ipv6TransportPayload { protocol, payload }),
        }
    }

    None
}

#[cfg(any(feature = "scan", feature = "traceroute"))]
pub(crate) fn extract_original_transport_v4(packet: &IcmpPacket) -> Option<OriginalTransport> {
    if !matches!(
        packet.get_icmp_type(),
        IcmpTypes::DestinationUnreachable | IcmpTypes::TimeExceeded | IcmpTypes::ParameterProblem
    ) {
        return None;
    }
    let payload = icmp_error_original_datagram(packet.payload())?;
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
    original_transport_from_payload(
        proto,
        inner_payload,
        IpAddr::V4(inner.get_source()),
        IpAddr::V4(inner.get_destination()),
    )
}

#[cfg(any(feature = "scan", feature = "traceroute"))]
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
    let payload = icmp_error_original_datagram(packet.payload())?;
    if payload.len() < Ipv6Packet::minimum_packet_size() {
        // An incomplete IPv6 header means we cannot trust the embedded transport data.
        return None;
    }
    let inner = Ipv6Packet::new(payload)?;
    let transport = ipv6_transport_payload(&inner)?;
    if transport.payload.len() < 4 {
        return None;
    }
    original_transport_from_payload(
        transport.protocol,
        transport.payload,
        IpAddr::V6(inner.get_source()),
        IpAddr::V6(inner.get_destination()),
    )
}

#[cfg(any(feature = "scan", feature = "traceroute"))]
fn original_transport_from_payload(
    proto: IpNextHeaderProtocol,
    inner_payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Option<OriginalTransport> {
    match proto {
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(inner_payload)?;
            Some(OriginalTransport {
                protocol: proto,
                source_ip,
                destination_ip,
                source: udp.get_source(),
                destination: udp.get_destination(),
                payload: udp.payload().to_vec(),
            })
        }
        IpNextHeaderProtocols::Tcp => {
            let payload = TcpPacket::new(inner_payload)
                .map(|tcp| tcp.payload().to_vec())
                .unwrap_or_default();
            Some(OriginalTransport {
                protocol: proto,
                source_ip,
                destination_ip,
                source: u16::from_be_bytes([inner_payload[0], inner_payload[1]]),
                destination: u16::from_be_bytes([inner_payload[2], inner_payload[3]]),
                payload,
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
                source_ip,
                destination_ip,
                source: u16::from_be_bytes([inner_payload[0], inner_payload[1]]),
                destination: u16::from_be_bytes([inner_payload[2], inner_payload[3]]),
                payload,
            })
        }
        _ => None,
    }
}

#[cfg(feature = "traceroute")]
pub(crate) fn extract_inner_echo_v4(packet: &IcmpPacket) -> Option<OriginalEcho> {
    if !matches!(
        packet.get_icmp_type(),
        IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable | IcmpTypes::ParameterProblem
    ) {
        return None;
    }
    let payload = icmp_error_original_datagram(packet.payload())?;
    if payload.len() < Ipv4Packet::minimum_packet_size() {
        // ICMP timeouts only carry the first bytes of the original datagram; ensure it is intact.
        return None;
    }
    let inner = Ipv4Packet::new(payload)?;
    if inner.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }
    let inner_payload = inner.payload();
    if inner_payload.len() < 8 {
        return None;
    }
    let echo = EchoRequestPacket::new(inner_payload)?;
    Some(OriginalEcho {
        source_ip: IpAddr::V4(inner.get_source()),
        destination_ip: IpAddr::V4(inner.get_destination()),
        identifier: echo.get_identifier(),
        sequence: echo.get_sequence_number(),
    })
}

#[cfg(feature = "traceroute")]
pub(crate) fn extract_inner_echo_v6(packet: &Icmpv6Packet) -> Option<OriginalEcho> {
    if !matches!(
        packet.get_icmpv6_type(),
        Icmpv6Types::DestinationUnreachable | Icmpv6Types::PacketTooBig | Icmpv6Types::TimeExceeded
    ) {
        return None;
    }
    let payload = icmp_error_original_datagram(packet.payload())?;
    if payload.len() < Ipv6Packet::minimum_packet_size() {
        return None;
    }
    let inner = Ipv6Packet::new(payload)?;
    let transport = ipv6_transport_payload(&inner)?;
    if transport.protocol != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }
    if transport.payload.len() < 4 {
        return None;
    }
    let inner_packet = Icmpv6Packet::new(transport.payload)?;
    let (identifier, sequence) = parse_icmpv6_echo(&inner_packet)?;
    Some(OriginalEcho {
        source_ip: IpAddr::V6(inner.get_source()),
        destination_ip: IpAddr::V6(inner.get_destination()),
        identifier,
        sequence,
    })
}

#[cfg(any(feature = "scan", feature = "traceroute"))]
fn icmp_error_original_datagram(payload: &[u8]) -> Option<&[u8]> {
    // Generic pnet ICMP/ICMPv6 packets expose the type-specific 32-bit
    // "rest of header" field as the first payload bytes. The embedded original
    // datagram starts after that field for error messages.
    payload.get(4..)
}

#[cfg(feature = "traceroute")]
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
mod tests {
    use super::*;
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::MutablePacket;

    fn ipv6_bytes(next: IpNextHeaderProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + payload.len()];
        let mut packet = MutableIpv6Packet::new(&mut bytes).unwrap();
        packet.set_version(6);
        packet.set_payload_length(payload.len() as u16);
        packet.set_next_header(next);
        packet.payload_mut().copy_from_slice(payload);
        bytes
    }

    fn packet(bytes: &[u8]) -> Ipv6Packet<'_> {
        Ipv6Packet::new(bytes).unwrap()
    }

    fn options_header(next: IpNextHeaderProtocol) -> [u8; 8] {
        [next.0, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn ipv6_transport_payload_returns_direct_transport_payload() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Udp, &payload);
        let parsed = packet(&bytes);
        let transport = ipv6_transport_payload(&parsed).unwrap();

        assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
        assert_eq!(transport.payload, payload);
    }

    #[test]
    fn ipv6_transport_payload_walks_options_and_routing_headers() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&options_header(IpNextHeaderProtocols::Ipv6Opts));
        payload.extend_from_slice(&options_header(IpNextHeaderProtocols::Ipv6Route));
        payload.extend_from_slice(&options_header(IpNextHeaderProtocols::Tcp));
        payload.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Hopopt, &payload);
        let parsed = packet(&bytes);
        let transport = ipv6_transport_payload(&parsed).unwrap();

        assert_eq!(transport.protocol, IpNextHeaderProtocols::Tcp);
        assert_eq!(transport.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_transport_payload_accepts_first_fragment() {
        let mut payload = vec![IpNextHeaderProtocols::Udp.0, 0, 0, 0, 0, 0, 0, 1];
        payload.extend_from_slice(&[9, 8, 7, 6]);
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Ipv6Frag, &payload);
        let parsed = packet(&bytes);
        let transport = ipv6_transport_payload(&parsed).unwrap();

        assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
        assert_eq!(transport.payload, &[9, 8, 7, 6]);
    }

    #[test]
    fn ipv6_transport_payload_rejects_nonzero_fragment_offset() {
        let payload = [
            IpNextHeaderProtocols::Udp.0,
            0,
            0,
            8,
            0,
            0,
            0,
            1,
            1,
            2,
            3,
            4,
        ];
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Ipv6Frag, &payload);

        assert!(ipv6_transport_payload(&packet(&bytes)).is_none());
    }

    #[test]
    fn ipv6_transport_payload_walks_ah_header() {
        let mut payload = vec![
            IpNextHeaderProtocols::Sctp.0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        payload.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Ah, &payload);
        let parsed = packet(&bytes);
        let transport = ipv6_transport_payload(&parsed).unwrap();

        assert_eq!(transport.protocol, IpNextHeaderProtocols::Sctp);
        assert_eq!(transport.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_transport_payload_rejects_no_next_header() {
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Ipv6NoNxt, &[]);

        assert!(ipv6_transport_payload(&packet(&bytes)).is_none());
    }

    #[test]
    fn ipv6_transport_payload_rejects_truncated_extension_headers() {
        let truncated_options = ipv6_bytes(
            IpNextHeaderProtocols::Hopopt,
            &[IpNextHeaderProtocols::Udp.0],
        );
        let truncated_fragment = ipv6_bytes(
            IpNextHeaderProtocols::Ipv6Frag,
            &[IpNextHeaderProtocols::Udp.0, 0, 0],
        );

        assert!(ipv6_transport_payload(&packet(&truncated_options)).is_none());
        assert!(ipv6_transport_payload(&packet(&truncated_fragment)).is_none());
    }

    #[test]
    fn ipv6_transport_payload_rejects_overlong_extension_chain() {
        let mut payload = Vec::new();
        for _ in 0..9 {
            payload.extend_from_slice(&options_header(IpNextHeaderProtocols::Hopopt));
        }
        payload.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = ipv6_bytes(IpNextHeaderProtocols::Hopopt, &payload);

        assert!(ipv6_transport_payload(&packet(&bytes)).is_none());
    }

    #[cfg(any(feature = "scan", feature = "traceroute"))]
    #[test]
    fn original_transport_from_payload_accepts_short_tcp_quote() {
        let quote = [0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 0];

        let original = original_transport_from_payload(
            IpNextHeaderProtocols::Tcp,
            &quote,
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(original.protocol, IpNextHeaderProtocols::Tcp);
        assert_eq!(original.source, 0x1234);
        assert_eq!(original.destination, 0xabcd);
        assert!(original.payload.is_empty());
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn parse_icmpv6_echo_extracts_identifier_and_sequence() {
        let bytes = [128, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd];
        let packet = Icmpv6Packet::new(&bytes).unwrap();

        assert_eq!(parse_icmpv6_echo(&packet), Some((0x1234, 0xabcd)));
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn parse_icmpv6_echo_rejects_short_payload() {
        let bytes = [128, 0, 0, 0, 0x12];
        let packet = Icmpv6Packet::new(&bytes).unwrap();

        assert_eq!(parse_icmpv6_echo(&packet), None);
    }
}
