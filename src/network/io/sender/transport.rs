// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use pnet::packet::icmp::{
    checksum as icmp_checksum, IcmpCode, IcmpType, IcmpTypes, MutableIcmpPacket,
};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Type, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use rand::random;
use thiserror::Error;

use crate::engine::spec::{IcmpSpec, Icmpv6Spec, TcpFlagSet, TcpSpec, TransportSpec, UdpSpec};
use crate::network::checksum::{
    compute_icmpv6_checksum, compute_tcp_checksum, compute_udp_checksum, ip_version_pair,
    IpVersionPair,
};

type Result<T> = std::result::Result<T, TransportBuildError>;

#[derive(Debug, Error)]
pub enum TransportBuildError {
    #[error("source and destination IP versions must match for {context}")]
    IpVersionMismatch { context: &'static str },
    #[error("TCP options exceed maximum supported header length of 60 bytes (got {length} bytes)")]
    TcpOptionsTooLong { length: usize },
    #[error("TCP header length must be a multiple of 4 bytes")]
    TcpHeaderAlignment,
    #[error("failed to allocate {protocol} packet")]
    AllocationFailed { protocol: &'static str },
    #[error("UDP datagram length {length} exceeds protocol maximum of {max} bytes; reduce the payload size")]
    UdpDatagramTooLong { length: usize, max: usize },
    #[error("ICMP transport requires an IPv4 destination; use --icmpv6 for IPv6 targets")]
    IcmpRequiresIpv4,
    #[error("ICMPv6 transport requires an IPv6 destination")]
    Icmpv6RequiresIpv6,
    #[error("ICMPv6 checksum requires IPv6 source and destination addresses")]
    Icmpv6ChecksumPairMismatch,
}

pub(crate) const TCP_HEADER_LEN: usize = 20;
pub(crate) const UDP_HEADER_LEN: usize = 8;

#[derive(Debug)]
pub struct TransportBuild {
    pub bytes: Vec<u8>,
    pub protocol: IpNextHeaderProtocol,
    pub label: &'static str,
}

pub fn build_transport_segment(
    transport: &TransportSpec,
    payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<TransportBuild> {
    match transport {
        TransportSpec::Auto => {
            let fallback = match destination_ip {
                IpAddr::V4(_) => TransportSpec::Icmp(IcmpSpec::default()),
                IpAddr::V6(_) => TransportSpec::Icmpv6(Icmpv6Spec::default()),
            };
            build_transport_segment(&fallback, payload, source_ip, destination_ip)
        }
        TransportSpec::Tcp(spec) => {
            let bytes = build_tcp_segment(spec, payload, source_ip, destination_ip)?;
            Ok(TransportBuild {
                bytes,
                protocol: IpNextHeaderProtocols::Tcp,
                label: "TCP",
            })
        }
        TransportSpec::Udp(spec) => {
            let bytes = build_udp_segment(spec, payload, source_ip, destination_ip)?;
            Ok(TransportBuild {
                bytes,
                protocol: IpNextHeaderProtocols::Udp,
                label: "UDP",
            })
        }
        TransportSpec::Icmp(spec) => {
            if !matches!(destination_ip, IpAddr::V4(_)) {
                return Err(TransportBuildError::IcmpRequiresIpv4);
            }
            let bytes = build_icmp_segment(spec, payload)?;
            Ok(TransportBuild {
                bytes,
                protocol: IpNextHeaderProtocols::Icmp,
                label: "ICMP",
            })
        }
        TransportSpec::Icmpv6(spec) => {
            if !matches!(destination_ip, IpAddr::V6(_)) {
                return Err(TransportBuildError::Icmpv6RequiresIpv6);
            }
            let bytes = build_icmpv6_segment(spec, payload, source_ip, destination_ip)?;
            Ok(TransportBuild {
                bytes,
                protocol: IpNextHeaderProtocols::Icmpv6,
                label: "ICMPv6",
            })
        }
    }
}

pub(crate) fn build_tcp_segment(
    spec: &TcpSpec,
    payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<Vec<u8>> {
    let options = spec.options.as_deref().unwrap_or(&[]);
    let header_len = TCP_HEADER_LEN + options.len();
    let packet_len = header_len + payload.len();

    let mut buffer = vec![0u8; packet_len];
    build_tcp_segment_into(spec, payload, source_ip, destination_ip, &mut buffer)?;
    Ok(buffer)
}

pub(crate) fn build_tcp_segment_into(
    spec: &TcpSpec,
    payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
    buffer: &mut [u8],
) -> Result<usize> {
    let ip_pair = ip_version_pair(source_ip, destination_ip).map_err(|_| {
        TransportBuildError::IpVersionMismatch {
            context: "TCP crafting",
        }
    })?;

    // Use the optimized builder, calculating flags here since we don't have them pre-calculated
    let flags = tcp_flags_value(&spec.flags);
    build_tcp_segment_optimized(spec, flags, payload, &ip_pair, buffer)
}

/// Optimized version of build_tcp_segment_into that accepts pre-validated IP pair and raw flags.
/// This avoids repetitive IP version checks and flag calculations in hot loops.
pub(crate) fn build_tcp_segment_optimized(
    spec: &TcpSpec,
    flags: u8,
    payload: &[u8],
    ip_pair: &IpVersionPair,
    buffer: &mut [u8],
) -> Result<usize> {
    let options = spec.options.as_deref().unwrap_or(&[]);
    let header_len = TCP_HEADER_LEN + options.len();
    if header_len > 60 {
        return Err(TransportBuildError::TcpOptionsTooLong { length: header_len });
    }

    let data_offset_words = (header_len / 4) as u8;
    if !header_len.is_multiple_of(4) {
        return Err(TransportBuildError::TcpHeaderAlignment);
    }

    let packet_len = header_len + payload.len();
    if buffer.len() < packet_len {
        return Err(TransportBuildError::AllocationFailed { protocol: "TCP" });
    }

    {
        let mut packet = MutableTcpPacket::new(&mut buffer[..packet_len])
            .ok_or(TransportBuildError::AllocationFailed { protocol: "TCP" })?;
        packet.set_source(spec.source_port.unwrap_or(0));
        packet.set_destination(spec.destination_port.unwrap_or(0));
        packet.set_sequence(spec.sequence.unwrap_or_else(random::<u32>));
        packet.set_acknowledgement(spec.acknowledgement.unwrap_or(0));
        packet.set_data_offset(data_offset_words);
        packet.set_flags(flags);
        packet.set_window(spec.window_size.unwrap_or(65_535));
        packet.set_urgent_ptr(0);
        packet.set_payload(payload);
        if !options.is_empty() {
            let packet_bytes = packet.packet_mut();
            let offset = TCP_HEADER_LEN;
            packet_bytes[offset..offset + options.len()].copy_from_slice(options);
        }
        packet.set_checksum(0);
        let checksum = compute_tcp_checksum(&packet, ip_pair);
        packet.set_checksum(checksum);
    }
    Ok(packet_len)
}

pub(crate) fn build_udp_segment(
    spec: &UdpSpec,
    payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<Vec<u8>> {
    let ip_pair = ip_version_pair(source_ip, destination_ip).map_err(|_| {
        TransportBuildError::IpVersionMismatch {
            context: "UDP crafting",
        }
    })?;
    let segment_length = UDP_HEADER_LEN + payload.len();
    if segment_length > u16::MAX as usize {
        return Err(TransportBuildError::UdpDatagramTooLong {
            length: segment_length,
            max: u16::MAX as usize,
        });
    }

    let mut buffer = vec![0u8; segment_length];
    {
        let mut packet = MutableUdpPacket::new(&mut buffer)
            .ok_or(TransportBuildError::AllocationFailed { protocol: "UDP" })?;
        packet.set_source(spec.source_port.unwrap_or(0));
        packet.set_destination(spec.destination_port.unwrap_or(0));
        packet.set_length(segment_length as u16);
        packet.set_payload(payload);
        packet.set_checksum(0);
        let checksum = compute_udp_checksum(&packet, &ip_pair);
        packet.set_checksum(finalize_udp_checksum(checksum));
    }
    Ok(buffer)
}

pub(crate) fn finalize_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

fn build_icmp_segment(spec: &IcmpSpec, payload: &[u8]) -> Result<Vec<u8>> {
    // 4 bytes ICMP header + 4 bytes rest of header + payload
    let packet_len = 4 + 4 + payload.len();
    let mut buffer = vec![0u8; packet_len];

    let icmp_type = spec
        .kind
        .map(IcmpType::new)
        .unwrap_or(IcmpTypes::EchoRequest);
    let icmp_code = spec.code.map(IcmpCode::new).unwrap_or(IcmpCode::new(0));

    {
        let mut packet = MutableIcmpPacket::new(&mut buffer)
            .ok_or(TransportBuildError::AllocationFailed { protocol: "ICMP" })?;
        packet.set_icmp_type(icmp_type);
        packet.set_icmp_code(icmp_code);
        packet.set_checksum(0);

        let payload_buffer = packet.payload_mut();

        match icmp_type {
            IcmpTypes::EchoRequest
            | IcmpTypes::EchoReply
            | IcmpTypes::Timestamp
            | IcmpTypes::TimestampReply
            | IcmpTypes::InformationRequest
            | IcmpTypes::InformationReply
            | IcmpTypes::AddressMaskRequest
            | IcmpTypes::AddressMaskReply => {
                let id = spec.identifier.unwrap_or_else(random::<u16>);
                let seq = spec.sequence.unwrap_or(0);
                payload_buffer[0..2].copy_from_slice(&id.to_be_bytes());
                payload_buffer[2..4].copy_from_slice(&seq.to_be_bytes());
            }
            _ => {
                // Use 0 (Unused) for the 4-byte parameter field unless identifier/sequence are provided.
                // We avoid generating random IDs here to prevent overwriting specific parameters for error types.
                if spec.identifier.is_some() || spec.sequence.is_some() {
                    let legacy = ((spec.identifier.unwrap_or(0) as u32) << 16)
                        | spec.sequence.unwrap_or(0) as u32;
                    payload_buffer[0..4].copy_from_slice(&legacy.to_be_bytes());
                } else {
                    payload_buffer[0..4].fill(0);
                }
            }
        }

        payload_buffer[4..].copy_from_slice(payload);

        let checksum = icmp_checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
    }
    Ok(buffer)
}

pub(crate) fn build_icmpv6_segment(
    spec: &Icmpv6Spec,
    payload: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<Vec<u8>> {
    let ip_pair = ip_version_pair(source_ip, destination_ip).map_err(|_| {
        TransportBuildError::IpVersionMismatch {
            context: "ICMPv6 checksum",
        }
    })?;
    let ip_pair = match ip_pair {
        pair @ IpVersionPair::V6(_, _) => pair,
        IpVersionPair::V4(_, _) => return Err(TransportBuildError::Icmpv6ChecksumPairMismatch),
    };
    let icmp_type = spec
        .kind
        .map(Icmpv6Type::new)
        .unwrap_or(Icmpv6Types::EchoRequest);
    let icmp_code = spec.code.map(Icmpv6Code::new).unwrap_or(Icmpv6Code(0));

    // Determine if the extra 4-byte "rest of header" field is needed.
    // Known types (Echo, Error) always require it. Unknown types only require
    // it when an identifier, sequence, or parameter is explicitly provided.
    let needs_rest_of_header = match icmp_type {
        Icmpv6Types::EchoRequest
        | Icmpv6Types::EchoReply
        | Icmpv6Types::DestinationUnreachable
        | Icmpv6Types::PacketTooBig
        | Icmpv6Types::TimeExceeded
        | Icmpv6Types::ParameterProblem => true,
        _ => spec.parameter.is_some() || spec.identifier.is_some() || spec.sequence.is_some(),
    };

    // 4 bytes ICMPv6 header + optional 4 bytes rest of header + payload
    let rest_of_header_len = if needs_rest_of_header { 4 } else { 0 };
    let packet_len = 4 + rest_of_header_len + payload.len();
    let mut buffer = vec![0u8; packet_len];

    {
        let mut packet = MutableIcmpv6Packet::new(&mut buffer)
            .ok_or(TransportBuildError::AllocationFailed { protocol: "ICMPv6" })?;
        packet.set_icmpv6_type(icmp_type);
        packet.set_icmpv6_code(icmp_code);
        packet.set_checksum(0);

        let payload_buffer = packet.payload_mut();

        if needs_rest_of_header {
            match icmp_type {
                Icmpv6Types::EchoRequest | Icmpv6Types::EchoReply => {
                    let id = spec.identifier.unwrap_or_else(random::<u16>);
                    let seq = spec.sequence.unwrap_or(0);
                    payload_buffer[0..2].copy_from_slice(&id.to_be_bytes());
                    payload_buffer[2..4].copy_from_slice(&seq.to_be_bytes());
                }
                Icmpv6Types::DestinationUnreachable
                | Icmpv6Types::PacketTooBig
                | Icmpv6Types::TimeExceeded
                | Icmpv6Types::ParameterProblem => {
                    payload_buffer[0..4]
                        .copy_from_slice(&icmpv6_error_parameter(spec).to_be_bytes());
                }
                _ => {
                    // Unknown type with explicit parameter/identifier/sequence
                    if let Some(parameter) = spec.parameter {
                        payload_buffer[0..4].copy_from_slice(&parameter.to_be_bytes());
                    } else {
                        let legacy = ((spec.identifier.unwrap_or(0) as u32) << 16)
                            | spec.sequence.unwrap_or(0) as u32;
                        payload_buffer[0..4].copy_from_slice(&legacy.to_be_bytes());
                    }
                }
            }
            payload_buffer[4..].copy_from_slice(payload);
        } else {
            // Unknown type with no extra header fields - payload follows immediately
            payload_buffer.copy_from_slice(payload);
        }

        let checksum = compute_icmpv6_checksum(&packet, &ip_pair)
            .map_err(|_| TransportBuildError::Icmpv6ChecksumPairMismatch)?;
        packet.set_checksum(checksum);
    }
    Ok(buffer)
}

fn icmpv6_error_parameter(spec: &Icmpv6Spec) -> u32 {
    if let Some(parameter) = spec.parameter {
        parameter
    } else if spec.identifier.is_some() || spec.sequence.is_some() {
        ((spec.identifier.unwrap_or(0) as u32) << 16) | spec.sequence.unwrap_or(0) as u32
    } else {
        0
    }
}

pub(crate) fn tcp_flags_value(flags: &TcpFlagSet) -> u8 {
    let mut value = 0u8;
    if flags.fin {
        value |= 0x01;
    }
    if flags.syn {
        value |= 0x02;
    }
    if flags.rst {
        value |= 0x04;
    }
    if flags.psh {
        value |= 0x08;
    }
    if flags.ack {
        value |= 0x10;
    }
    if flags.urg {
        value |= 0x20;
    }
    if flags.ece {
        value |= 0x40;
    }
    if flags.cwr {
        value |= 0x80;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{IcmpSpec, Icmpv6Spec, TcpFlagSet, TcpSpec, UdpSpec};
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::icmpv6::Icmpv6Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn udp_zero_checksum_is_transmitted_as_all_ones() {
        assert_eq!(finalize_udp_checksum(0), 0xFFFF);
        assert_eq!(finalize_udp_checksum(0xBEEF), 0xBEEF);
        assert_eq!(finalize_udp_checksum(0xFFFF), 0xFFFF);
        assert_eq!(finalize_udp_checksum(1), 1);
    }

    #[test]
    fn build_tcp_segment_rejects_options_too_long() {
        let spec = TcpSpec {
            options: Some(vec![0u8; 44]), // TCP_HEADER_LEN (20) + 44 = 64 > 60
            ..Default::default()
        };
        let result = build_tcp_segment(
            &spec,
            &[],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert!(matches!(
            result,
            Err(TransportBuildError::TcpOptionsTooLong { length: 64 })
        ));
    }

    #[test]
    fn build_tcp_segment_rejects_misaligned_options() {
        let spec = TcpSpec {
            options: Some(vec![0u8; 1]), // 20 + 1 = 21, not divisible by 4
            ..Default::default()
        };
        let result = build_tcp_segment(
            &spec,
            &[],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert!(matches!(
            result,
            Err(TransportBuildError::TcpHeaderAlignment)
        ));
    }

    #[test]
    fn build_udp_segment_rejects_too_large_payload() {
        // Max u16 65535. Header 8. Max payload 65527. Try 65528.
        let payload = vec![0u8; 65528];
        let spec = UdpSpec::default();
        let result = build_udp_segment(
            &spec,
            &payload,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        assert!(matches!(
            result,
            Err(TransportBuildError::UdpDatagramTooLong {
                length: 65536,
                max: 65535
            })
        ));
    }

    #[test]
    fn tcp_flags_value_correctly_maps_flags() {
        let flags = TcpFlagSet {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        // SYN(0x02) | ACK(0x10) -> 0x12
        assert_eq!(tcp_flags_value(&flags), 0x12);

        let all_flags = TcpFlagSet {
            syn: true,
            ack: true,
            fin: true,
            rst: true,
            psh: true,
            urg: true,
            ece: true,
            cwr: true,
        };
        // FIN|SYN|RST|PSH|ACK|URG (0x3F) + ECE + CWR = 0xFF
        assert_eq!(tcp_flags_value(&all_flags), 0xFF);
    }

    #[test]
    fn build_icmp_segment_structure() {
        let spec = IcmpSpec {
            kind: Some(8), // Echo Request
            code: Some(0),
            identifier: Some(0x1234),
            sequence: Some(0x5678),
        };
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let result = build_icmp_segment(&spec, &payload).expect("ICMP build failed");
        let packet = IcmpPacket::new(&result).expect("valid ICMP packet");

        assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(packet.get_icmp_code(), IcmpCode::new(0));
        assert_ne!(packet.get_checksum(), 0);

        let body = packet.payload();
        assert_eq!(body.len(), 4 + 4); // 4B id+seq, 4B payload
        assert_eq!(body[0..2], [0x12, 0x34]); // Identifier
        assert_eq!(body[2..4], [0x56, 0x78]); // Sequence
        assert_eq!(body[4..], payload);
    }

    #[test]
    fn build_icmpv6_segment_structure() {
        let spec = Icmpv6Spec {
            kind: Some(128), // Echo Request
            code: Some(0),
            identifier: Some(0xABCD),
            sequence: Some(0x0123),
            parameter: None,
        };
        let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let result = build_icmpv6_segment(&spec, &payload, src, dst).expect("ICMPv6 build failed");
        let packet = Icmpv6Packet::new(&result).expect("valid ICMPv6 packet");

        assert_eq!(packet.get_icmpv6_type(), Icmpv6Types::EchoRequest);
        assert_eq!(packet.get_icmpv6_code(), Icmpv6Code::new(0));
        assert_ne!(packet.get_checksum(), 0);

        let body = packet.payload();
        assert_eq!(body.len(), 4 + 4); // 4B id+seq, 4B payload
        assert_eq!(body[0..2], [0xAB, 0xCD]); // Identifier
        assert_eq!(body[2..4], [0x01, 0x23]); // Sequence
        assert_eq!(body[4..], payload);
    }

    #[test]
    fn build_tcp_segment_content() {
        let spec = TcpSpec {
            source_port: Some(1234),
            destination_port: Some(80),
            sequence: Some(1000),
            acknowledgement: Some(2000),
            window_size: Some(4096),
            flags: TcpFlagSet {
                syn: true,
                ..Default::default()
            },
            options: None,
        };
        let payload = vec![0x01, 0x02, 0x03];
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let result = build_tcp_segment(&spec, &payload, src, dst).expect("TCP build failed");
        let packet = TcpPacket::new(&result).expect("valid TCP packet");

        assert_eq!(packet.get_source(), 1234);
        assert_eq!(packet.get_destination(), 80);
        assert_eq!(packet.get_sequence(), 1000);
        assert_eq!(packet.get_acknowledgement(), 2000);
        assert_eq!(packet.get_window(), 4096);
        assert_eq!(packet.get_flags(), pnet::packet::tcp::TcpFlags::SYN);
        assert_eq!(packet.payload(), payload.as_slice());
        assert_ne!(packet.get_checksum(), 0);
    }

    #[test]
    fn build_udp_segment_content() {
        let spec = UdpSpec {
            source_port: Some(53),
            destination_port: Some(12345),
        };
        let payload = vec![0xFF; 10];
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let result = build_udp_segment(&spec, &payload, src, dst).expect("UDP build failed");
        let packet = UdpPacket::new(&result).expect("valid UDP packet");

        assert_eq!(packet.get_source(), 53);
        assert_eq!(packet.get_destination(), 12345);
        assert_eq!(packet.get_length(), 8 + 10);
        assert_eq!(packet.payload(), payload.as_slice());
        assert_ne!(packet.get_checksum(), 0);
    }

    #[test]
    fn build_transport_segment_auto_fallback() {
        let payload = b"ping";
        let src_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dst_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let build_v4 = build_transport_segment(&TransportSpec::Auto, payload, src_v4, dst_v4)
            .expect("Auto build IPv4");
        assert_eq!(build_v4.protocol, IpNextHeaderProtocols::Icmp);
        assert_eq!(build_v4.label, "ICMP");

        let src_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let build_v6 = build_transport_segment(&TransportSpec::Auto, payload, src_v6, dst_v6)
            .expect("Auto build IPv6");
        assert_eq!(build_v6.protocol, IpNextHeaderProtocols::Icmpv6);
        assert_eq!(build_v6.label, "ICMPv6");
    }
}

#[test]
fn build_icmp_segment_destination_unreachable_structure() {
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::Packet;
    let spec = IcmpSpec {
        kind: Some(3), // Destination Unreachable
        code: Some(0),
        identifier: None,
        sequence: None,
    };
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let result = build_icmp_segment(&spec, &payload).expect("ICMP build failed");
    let packet = IcmpPacket::new(&result).expect("valid ICMP packet");

    assert_eq!(packet.get_icmp_type(), IcmpTypes::DestinationUnreachable);
    assert_eq!(packet.get_icmp_code(), IcmpCode::new(0));

    let body = packet.payload();
    assert_eq!(body.len(), 4 + 4); // 4B unused/param + 4B payload
                                   // Should be zero filled because identifier/sequence are None
    assert_eq!(body[0..4], [0, 0, 0, 0]);
    assert_eq!(body[4..], payload);
}
