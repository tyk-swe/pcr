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

use crate::domain::spec::{IcmpSpec, Icmpv6Spec, TcpFlagSet, TcpSpec, TransportSpec, UdpSpec};
use crate::network::checksum::{
    compute_icmpv6_checksum, compute_tcp_checksum, compute_udp_checksum, ip_version_pair,
    IpVersionPair,
};

type Result<T> = std::result::Result<T, TransportBuildError>;

#[derive(Debug, Error)]
pub(crate) enum TransportBuildError {
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
pub(super) struct TransportBuild {
    pub bytes: Vec<u8>,
    pub protocol: IpNextHeaderProtocol,
    pub label: &'static str,
}

pub(super) fn build_transport_segment(
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
