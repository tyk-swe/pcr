// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Wire correlation and probe identity shared by DNS, scan, and traceroute.

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::field::{FieldValue, WireValue};
use packetcraftr_core::protocol::{
    IcmpErrorKind, QuotedTransport, SctpResponseKind,
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    quoted_icmp_error, sctp_response_kind,
    transport::{Sctp, Tcp},
    transport_tuple_reversed,
};
use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet, protocol::BuiltinProtocol,
    protocol::semantics, registry::Registry,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    #[default]
    Udp,
    Sctp,
    Icmp,
    Ip,
}

impl Transport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An IPv4 identification native raw-socket adapters can preserve exactly; zero is excluded.
pub(crate) const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

/// Sent-probe matching rebuilds the payload, so the 16-bit sequence reduction is symmetric.
pub(crate) fn icmp_identity(tag: u8, sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, tag, (sequence >> 8) as u8, sequence as u8])
}

pub(crate) const EPHEMERAL_SOURCE_PORT_BASE: u16 = 49_152;

// `rotated` is reduced modulo the range width, so `range_start + rotated` fits in u16.
pub(crate) fn ephemeral_source_port(base: u16, offset: u64) -> u16 {
    let (range_start, width) = if base >= EPHEMERAL_SOURCE_PORT_BASE {
        (
            u32::from(EPHEMERAL_SOURCE_PORT_BASE),
            u32::from(u16::MAX)
                .saturating_sub(u32::from(EPHEMERAL_SOURCE_PORT_BASE))
                .saturating_add(1),
        )
    } else {
        (1, u32::from(EPHEMERAL_SOURCE_PORT_BASE).saturating_sub(1))
    };
    let offset = offset.checked_rem(u64::from(width)).unwrap_or(0) as u32;
    let rotated = u32::from(base)
        .saturating_sub(range_start)
        .saturating_add(offset)
        .checked_rem(width)
        .unwrap_or(0);
    range_start.saturating_add(rotated) as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Correlation {
    TcpReset,
    TcpSynAck,
    TcpOther,
    UdpReply,
    SctpInitAck,
    SctpAbort,
    SctpOther,
    IcmpReply,
    IcmpTimestampReply,
    IcmpNetmaskReply,
    IpProtocolReply,
    PortUnreachable,
    ProtocolUnreachable,
    TimeExceeded,
    AdministrativelyProhibited,
    DestinationUnreachable,
}

impl Correlation {
    pub(crate) const fn is_direct_reply(self) -> bool {
        matches!(
            self,
            Self::TcpReset
                | Self::TcpSynAck
                | Self::TcpOther
                | Self::UdpReply
                | Self::SctpInitAck
                | Self::SctpAbort
                | Self::SctpOther
                | Self::IcmpReply
                | Self::IcmpTimestampReply
                | Self::IcmpNetmaskReply
                | Self::IpProtocolReply
        )
    }

    pub(crate) const fn is_network_failure(self) -> bool {
        !self.is_direct_reply()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) responder: IpAddr,
    pub(crate) reason: &'static str,
    pub(crate) correlation: Correlation,
}

impl Observation {
    const fn new(responder: IpAddr, correlation: Correlation, reason: &'static str) -> Self {
        Self {
            responder,
            reason,
            correlation,
        }
    }
}

pub(crate) fn packet_shape_matches(packet: &Packet, expected: &[BuiltinProtocol]) -> bool {
    shape_matches(packet, expected, 0)
}

/// Like [`packet_shape_matches`], with exactly one more layer of any kind after `expected`.
pub(crate) fn packet_shape_with_payload_matches(
    packet: &Packet,
    expected: &[BuiltinProtocol],
) -> bool {
    shape_matches(packet, expected, 1)
}

fn shape_matches(packet: &Packet, expected: &[BuiltinProtocol], trailing: usize) -> bool {
    let mut layers = packet.iter().peekable();
    if layers
        .peek()
        .is_some_and(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
    {
        layers.next();
    }
    expected.iter().all(|expected| {
        layers
            .next()
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(*expected))
    }) && layers.count() == trailing
}

pub(crate) fn observe(
    registry: &Registry,
    transport: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<Observation> {
    if response
        .diagnostics
        .iter()
        .any(Diagnostic::is_checksum_failure)
    {
        return None;
    }
    let responder = semantics::outer_ip_path(&response.packet).ok()??.source;
    if let Some(observation) = classify_icmp_error(transport, request, &response.packet, responder)
    {
        return Some(observation);
    }
    // UDP probes leave DNS identity to the workflow but must reverse the entire tunnel stack.
    let udp_responder = (transport == Transport::Udp)
        .then(|| transport_tuple_reversed(request, &response.packet, BuiltinProtocol::Udp))
        .flatten();
    let ip_responder = (transport == Transport::Ip)
        .then(|| direct_ip_protocol_reply(request, &response.packet))
        .flatten();
    let (direct_reply, direct_responder) = if let Some(responder) = udp_responder.or(ip_responder) {
        (true, Some(responder))
    } else {
        match request
            .iter()
            .filter_map(|layer| registry.matcher(layer.protocol_id().as_str()))
            .filter_map(|matcher| {
                let matched = matcher.matches(request, &response.packet)?;
                Some((matcher, matched))
            })
            .max_by_key(|(_, matched)| matched.confidence)
        {
            Some((matcher, _)) => (true, matcher.responder(request, &response.packet)),
            None => (false, None),
        }
    };
    if direct_reply {
        let responder = direct_responder.unwrap_or(responder);
        let observation = match transport {
            Transport::Tcp => {
                let tcp = response.packet.get::<Tcp>()?;
                let flags = tcp.flags;
                if flags & Tcp::RST != 0 {
                    Observation::new(responder, Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request.get::<Tcp>()?;
                    if request_tcp.flags & Tcp::SYN == 0 {
                        Observation::new(
                            responder,
                            Correlation::TcpOther,
                            "correlated TCP SYN/ACK to a probe without SYN",
                        )
                    } else {
                        Observation::new(
                            responder,
                            Correlation::TcpSynAck,
                            "correlated TCP SYN/ACK",
                        )
                    }
                } else {
                    Observation::new(
                        responder,
                        Correlation::TcpOther,
                        "correlated TCP response with inconclusive flags",
                    )
                }
            }
            Transport::Udp => Observation::new(
                responder,
                Correlation::UdpReply,
                "correlated UDP response from the requested endpoint",
            ),
            Transport::Sctp => {
                let request_sctp = request.get::<Sctp>()?;
                let sctp_index = response
                    .packet
                    .iter()
                    .rposition(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Sctp))?;
                match sctp_response_kind(&response.packet, sctp_index)? {
                    SctpResponseKind::InitAck if request_sctp.verification_tag == 0 => {
                        Observation::new(
                            responder,
                            Correlation::SctpInitAck,
                            "correlated SCTP INIT ACK",
                        )
                    }
                    SctpResponseKind::InitAck => Observation::new(
                        responder,
                        Correlation::SctpOther,
                        "correlated SCTP INIT ACK to a COOKIE ECHO probe",
                    ),
                    SctpResponseKind::Abort => {
                        Observation::new(responder, Correlation::SctpAbort, "correlated SCTP ABORT")
                    }
                    SctpResponseKind::Other => Observation::new(
                        responder,
                        Correlation::SctpOther,
                        "correlated SCTP response with inconclusive chunk",
                    ),
                }
            }
            Transport::Icmp => match response.packet.get::<Icmpv4>().map(|icmp| icmp.icmp_type) {
                Some(14) => Observation::new(
                    responder,
                    Correlation::IcmpTimestampReply,
                    "correlated ICMP timestamp reply",
                ),
                Some(18) => Observation::new(
                    responder,
                    Correlation::IcmpNetmaskReply,
                    "correlated ICMP address mask reply",
                ),
                _ => Observation::new(
                    responder,
                    Correlation::IcmpReply,
                    "correlated ICMP echo reply",
                ),
            },
            Transport::Ip => Observation::new(
                responder,
                Correlation::IpProtocolReply,
                "correlated IP protocol response",
            ),
        };
        return Some(observation);
    }

    None
}

fn direct_ip_protocol_reply(request: &Packet, response: &Packet) -> Option<IpAddr> {
    if !request.iter().all(|layer| {
        matches!(
            BuiltinProtocol::of(layer),
            Some(
                BuiltinProtocol::Ethernet
                    | BuiltinProtocol::Ipv4
                    | BuiltinProtocol::Ipv6
                    | BuiltinProtocol::Padding
            )
        )
    }) {
        return None;
    }
    if response
        .get::<Icmpv4>()
        .is_some_and(|icmp| matches!(icmp.icmp_type, 3 | 4 | 5 | 11 | 12))
        || response
            .get::<Icmpv6>()
            .is_some_and(|icmp| icmp.icmp_type < 128)
    {
        return None;
    }
    let request_path = semantics::outer_ip_path(request).ok()??;
    let response_path = semantics::outer_ip_path(response).ok()??;
    if request_path.source != response_path.final_destination
        || request_path.final_destination != response_path.source
    {
        return None;
    }
    let protocol_matches = match (request.get::<Ipv4>(), response.get::<Ipv4>()) {
        (Some(req), Some(resp)) => {
            matches!((&req.protocol, &resp.protocol), (WireValue::Exact(a), WireValue::Exact(b)) if a == b)
        }
        _ => match (request.get::<Ipv6>(), response.get::<Ipv6>()) {
            (Some(req), Some(resp)) => match req.next_header {
                WireValue::Exact(protocol) => {
                    matches!(resp.next_header, WireValue::Exact(value) if value == protocol)
                        || semantics::outer_layers(response)
                            .skip_while(|layer| !layer.is::<Ipv6>())
                            .skip(1)
                            .take_while(|layer| {
                                BuiltinProtocol::of(*layer)
                                    .is_some_and(BuiltinProtocol::is_ipv6_extension)
                            })
                            .any(|layer| {
                                matches!(layer.field("next_header"), Some(FieldValue::Unsigned(value)) if value == u64::from(protocol))
                            })
                }
                _ => false,
            },
            _ => false,
        },
    };
    protocol_matches.then_some(response_path.source)
}

fn classify_icmp_error(
    transport: Transport,
    request: &Packet,
    response: &Packet,
    responder: IpAddr,
) -> Option<Observation> {
    let expected_transport = match transport {
        Transport::Tcp => QuotedTransport::Tcp,
        Transport::Udp => QuotedTransport::Udp,
        Transport::Sctp => QuotedTransport::Sctp,
        Transport::Icmp => QuotedTransport::Icmp,
        Transport::Ip => QuotedTransport::Ip,
    };
    let kind = quoted_icmp_error(request, response, expected_transport)?;
    let icmp_protocol = response
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(protocol @ (BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)) => Some(protocol),
            _ => None,
        })?;
    let ipv6 = icmp_protocol == BuiltinProtocol::Icmpv6;
    let (correlation, ipv4_reason, ipv6_reason) = match kind {
        IcmpErrorKind::PortUnreachable => (
            Correlation::PortUnreachable,
            "ICMPv4 port unreachable",
            "ICMPv6 port unreachable",
        ),
        IcmpErrorKind::ProtocolUnreachable => (
            Correlation::ProtocolUnreachable,
            "ICMPv4 protocol unreachable",
            "ICMPv6 unrecognized next header",
        ),
        IcmpErrorKind::AdministrativelyProhibited => (
            Correlation::AdministrativelyProhibited,
            "ICMPv4 administratively prohibited",
            "ICMPv6 policy or administrative rejection",
        ),
        IcmpErrorKind::DestinationUnreachable => (
            Correlation::DestinationUnreachable,
            "ICMPv4 destination unreachable",
            "ICMPv6 destination unreachable",
        ),
        IcmpErrorKind::TimeExceeded => (
            Correlation::TimeExceeded,
            "ICMPv4 time exceeded before reaching the endpoint",
            "ICMPv6 time exceeded before reaching the endpoint",
        ),
    };
    let reason = if ipv6 { ipv6_reason } else { ipv4_reason };
    Some(Observation::new(responder, correlation, reason))
}
