// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private wire correlation shared by probe-based workflows.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::{
    Packet, codec::NetworkEnvelope, decode::DecodedPacket, diagnostic::DiagnosticSeverity,
    field::FieldValue, registry::ProtocolRegistry,
};
use crate::protocol::transport::Tcp;

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

pub(super) fn packet_shape_matches(packet: &Packet, expected: &[&str]) -> bool {
    let mut layers = packet.iter().peekable();
    if layers
        .peek()
        .is_some_and(|layer| layer.protocol_id().as_str() == "ethernet")
    {
        layers.next();
    }
    expected.iter().all(|expected| {
        layers
            .next()
            .is_some_and(|layer| layer.protocol_id().as_str() == *expected)
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
    let responder = network_envelope(&response.packet)?.source;
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
                    .find(|layer| layer.protocol_id().as_str() == "tcp")?;
                let flags = u16::try_from(tcp.field("flags")?.as_u64()?).ok()?;
                if flags & Tcp::RST != 0 {
                    Observation::new(responder, Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request
                        .iter()
                        .find(|layer| layer.protocol_id().as_str() == "tcp")?;
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

    classify_icmp_error(transport, request, &response.packet, responder)
}

fn classify_icmp_error(
    transport: Transport,
    request: &Packet,
    response: &Packet,
    responder: IpAddr,
) -> Option<Observation> {
    let request_source = network_envelope(request)?.source;
    let response_destination = network_envelope(response)?.destination;
    if request_source != response_destination {
        return None;
    }
    let layer = response
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "icmpv4" | "icmpv6"))?;
    let icmp_type = u8::try_from(layer.field("type")?.as_u64()?).ok()?;
    let code = u8::try_from(layer.field("code")?.as_u64()?).ok()?;
    let FieldValue::Bytes(body) = layer.field("body")? else {
        return None;
    };
    let quote = body.get(4..)?;
    if !quoted_probe_matches(transport, request, quote) {
        return None;
    }
    let observation = |correlation, reason| Some(Observation::new(responder, correlation, reason));
    match layer.protocol_id().as_str() {
        "icmpv4" if icmp_type == 3 => match code {
            3 if transport == Transport::Udp => {
                observation(Correlation::PortUnreachable, "ICMPv4 port unreachable")
            }
            9 | 10 | 13 => observation(
                Correlation::AdministrativelyProhibited,
                "ICMPv4 administratively prohibited",
            ),
            _ => observation(
                Correlation::DestinationUnreachable,
                "ICMPv4 destination unreachable",
            ),
        },
        "icmpv4" if icmp_type == 11 => observation(
            Correlation::TimeExceeded,
            "ICMPv4 time exceeded before reaching the endpoint",
        ),
        "icmpv6" if icmp_type == 1 => match code {
            4 if transport == Transport::Udp => {
                observation(Correlation::PortUnreachable, "ICMPv6 port unreachable")
            }
            1 | 5 | 6 => observation(
                Correlation::AdministrativelyProhibited,
                "ICMPv6 policy or administrative rejection",
            ),
            _ => observation(
                Correlation::DestinationUnreachable,
                "ICMPv6 destination unreachable",
            ),
        },
        "icmpv6" if icmp_type == 3 => observation(
            Correlation::TimeExceeded,
            "ICMPv6 time exceeded before reaching the endpoint",
        ),
        _ => None,
    }
}

fn quoted_probe_matches(transport: Transport, request: &Packet, quote: &[u8]) -> bool {
    let Some(quoted) = parse_quoted_probe(quote) else {
        return false;
    };
    let Some(network) = network_envelope(request) else {
        return false;
    };
    if quoted.source != network.source || quoted.destination != network.destination {
        return false;
    }
    match transport {
        Transport::Tcp | Transport::Udp => {
            let (protocol_name, protocol_number) = if transport == Transport::Tcp {
                ("tcp", 6)
            } else {
                ("udp", 17)
            };
            if quoted.protocol != protocol_number {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == protocol_name)
            else {
                return false;
            };
            let Some(source_port) = layer
                .field("source_port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
            else {
                return false;
            };
            let Some(destination_port) = layer
                .field("destination_port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
            else {
                return false;
            };
            let source_port = source_port.to_be_bytes();
            let destination_port = destination_port.to_be_bytes();
            if quoted.payload.get(..4)
                != Some(
                    &[
                        source_port[0],
                        source_port[1],
                        destination_port[0],
                        destination_port[1],
                    ][..],
                )
            {
                return false;
            }
            if transport == Transport::Tcp {
                let Some(sequence) = layer
                    .field("sequence")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                else {
                    return false;
                };
                quoted.payload.get(4..8) == Some(&sequence.to_be_bytes()[..])
            } else {
                true
            }
        }
        Transport::Icmp => {
            let (protocol, name) = if network.source.is_ipv4() {
                (1, "icmpv4")
            } else {
                (58, "icmpv6")
            };
            if quoted.protocol != protocol {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == name)
            else {
                return false;
            };
            let Some(icmp_type) = layer
                .field("type")
                .and_then(|value| value.as_u64())
                .and_then(|value| u8::try_from(value).ok())
            else {
                return false;
            };
            let Some(code) = layer
                .field("code")
                .and_then(|value| value.as_u64())
                .and_then(|value| u8::try_from(value).ok())
            else {
                return false;
            };
            let Some(FieldValue::Bytes(body)) = layer.field("body") else {
                return false;
            };
            quoted.payload.len() >= 8
                && quoted.payload[0] == icmp_type
                && quoted.payload[1] == code
                && body.len() >= 4
                && quoted.payload[4..8] == body[..4]
        }
    }
}

struct QuotedProbe<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

fn parse_quoted_probe(bytes: &[u8]) -> Option<QuotedProbe<'_>> {
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let header_len = usize::from(bytes[0] & 0x0f).checked_mul(4)?;
            if header_len < 20 || bytes.len() < header_len + 8 {
                return None;
            }
            let fragment_offset = u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                destination: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                protocol: bytes[9],
                payload: &bytes[header_len..],
            })
        }
        6 => {
            if bytes.len() < 48 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                protocol: bytes[6],
                payload: &bytes[40..],
            })
        }
        _ => None,
    }
}

fn network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        let source = match layer.field("source")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        let destination = match layer.field("destination")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        Some(NetworkEnvelope {
            source,
            destination,
        })
    })
}
