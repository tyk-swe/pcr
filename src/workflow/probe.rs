// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private wire correlation shared by probe-based workflows.

use std::net::IpAddr;

use crate::packet::{
    Packet,
    decode::DecodedPacket,
    diagnostic::DiagnosticSeverity,
    registry::ProtocolRegistry,
    semantics::{self, BuiltinProtocol},
};
use crate::protocol::{
    QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind, transport::Tcp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Transport {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Correlation {
    TcpReset,
    TcpSynAck,
    TcpOther,
    UdpReply,
    IcmpReply,
    PortUnreachable,
    TimeExceeded,
    AdministrativelyProhibited,
    DestinationUnreachable,
}

impl Correlation {
    pub(super) const fn is_direct_reply(self) -> bool {
        matches!(
            self,
            Self::TcpReset | Self::TcpSynAck | Self::TcpOther | Self::UdpReply | Self::IcmpReply
        )
    }

    pub(super) const fn is_network_failure(self) -> bool {
        !self.is_direct_reply()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) responder: IpAddr,
    pub(super) reason: &'static str,
    pub(super) correlation: Correlation,
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

pub(super) fn packet_shape_matches(packet: &Packet, expected: &[BuiltinProtocol]) -> bool {
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
    }) && layers.next().is_none()
}

/// Correlates one decoded response with a request without assigning an
/// operation-specific status. Corrupt and unrelated traffic returns `None`.
pub(super) fn observe(
    registry: &ProtocolRegistry,
    transport: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<Observation> {
    if response.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
    }) {
        return None;
    }
    let responder = semantics::outer_ip_path(&response.packet).ok()??.source;
    if let Some(observation) = classify_icmp_error(transport, request, &response.packet, responder)
    {
        return Some(observation);
    }
    let direct_match = request
        .iter()
        .filter_map(|layer| registry.matcher(&layer.protocol_id()))
        .filter_map(|matcher| {
            let result = matcher.matches(request, &response.packet);
            result.matched.then_some((matcher, result))
        })
        .max_by_key(|(_, result)| result.confidence);
    if let Some((matcher, _)) = direct_match {
        let responder = matcher
            .responder(request, &response.packet)
            .unwrap_or(responder);
        let observation = match transport {
            Transport::Tcp => {
                let tcp = response
                    .packet
                    .iter()
                    .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Tcp))?;
                let flags = u16::try_from(tcp.field("flags")?.as_u64()?).ok()?;
                if flags & Tcp::RST != 0 {
                    Observation::new(responder, Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request
                        .iter()
                        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Tcp))?;
                    let request_sequence =
                        u32::try_from(request_tcp.field("sequence")?.as_u64()?).ok()?;
                    let acknowledgment =
                        u32::try_from(tcp.field("acknowledgment")?.as_u64()?).ok()?;
                    if acknowledgment != request_sequence.wrapping_add(1) {
                        return None;
                    }
                    Observation::new(responder, Correlation::TcpSynAck, "correlated TCP SYN/ACK")
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
            Transport::Icmp => Observation::new(
                responder,
                Correlation::IcmpReply,
                "correlated ICMP echo reply",
            ),
        };
        return Some(observation);
    }

    None
}

fn classify_icmp_error(
    transport: Transport,
    request: &Packet,
    response: &Packet,
    responder: IpAddr,
) -> Option<Observation> {
    let expected_transport = match transport {
        Transport::Tcp => QuotedProbeTransport::Tcp,
        Transport::Udp => QuotedProbeTransport::Udp,
        Transport::Icmp => QuotedProbeTransport::Icmp,
    };
    let kind = quoted_icmp_error_kind(request, response, expected_transport)?;
    let icmp_protocol = response
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(protocol @ (BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)) => Some(protocol),
            _ => None,
        })?;
    let ipv6 = icmp_protocol == BuiltinProtocol::Icmpv6;
    let (correlation, reason) = match (kind, ipv6) {
        (QuotedIcmpError::PortUnreachable, false) => {
            (Correlation::PortUnreachable, "ICMPv4 port unreachable")
        }
        (QuotedIcmpError::PortUnreachable, true) => {
            (Correlation::PortUnreachable, "ICMPv6 port unreachable")
        }
        (QuotedIcmpError::AdministrativelyProhibited, false) => (
            Correlation::AdministrativelyProhibited,
            "ICMPv4 administratively prohibited",
        ),
        (QuotedIcmpError::AdministrativelyProhibited, true) => (
            Correlation::AdministrativelyProhibited,
            "ICMPv6 policy or administrative rejection",
        ),
        (QuotedIcmpError::DestinationUnreachable, false) => (
            Correlation::DestinationUnreachable,
            "ICMPv4 destination unreachable",
        ),
        (QuotedIcmpError::DestinationUnreachable, true) => (
            Correlation::DestinationUnreachable,
            "ICMPv6 destination unreachable",
        ),
        (QuotedIcmpError::TimeExceeded, false) => (
            Correlation::TimeExceeded,
            "ICMPv4 time exceeded before reaching the endpoint",
        ),
        (QuotedIcmpError::TimeExceeded, true) => (
            Correlation::TimeExceeded,
            "ICMPv6 time exceeded before reaching the endpoint",
        ),
    };
    Some(Observation::new(responder, correlation, reason))
}
