// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private wire correlation shared by probe-based workflows.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::internal::{
    DecodedPacket, DiagnosticSeverity, FieldValue, Packet, ProtocolRegistry,
};
use crate::protocol::internal::Tcp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Correlation {
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
    pub(crate) const fn is_direct_reply(self) -> bool {
        matches!(
            self,
            Self::TcpReset | Self::TcpSynAck | Self::TcpOther | Self::UdpReply | Self::IcmpReply
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

/// Correlates one decoded response with a request without assigning an
/// operation-specific status. Corrupt and unrelated traffic returns `None`.
pub(crate) fn observe(
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
    let responder = ip_tuple(&response.packet)?.0;
    let direct_match = request
        .iter()
        .filter_map(|layer| registry.matcher(&layer.protocol_id()))
        .map(|matcher| matcher.matches(request, &response.packet))
        .any(|result| result.matched);
    if direct_match {
        let (correlation, reason) = match transport {
            Transport::Tcp => {
                let tcp = response
                    .packet
                    .iter()
                    .find(|layer| layer.protocol_id().as_str() == "tcp")?;
                let flags = tcp.field("flags")?.as_u64()? as u16;
                if flags & Tcp::RST != 0 {
                    (Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request
                        .iter()
                        .find(|layer| layer.protocol_id().as_str() == "tcp")?;
                    let request_sequence = request_tcp.field("sequence")?.as_u64()? as u32;
                    let acknowledgment = tcp.field("acknowledgment")?.as_u64()? as u32;
                    if acknowledgment != request_sequence.wrapping_add(1) {
                        return None;
                    }
                    (Correlation::TcpSynAck, "correlated TCP SYN/ACK")
                } else {
                    (
                        Correlation::TcpOther,
                        "correlated TCP response with inconclusive flags",
                    )
                }
            }
            Transport::Udp => (
                Correlation::UdpReply,
                "correlated UDP response from the requested endpoint",
            ),
            Transport::Icmp => (Correlation::IcmpReply, "correlated ICMP echo reply"),
        };
        return Some(Observation {
            responder,
            reason,
            correlation,
        });
    }

    classify_icmp_error(transport, request, &response.packet).map(|(correlation, reason)| {
        Observation {
            responder,
            reason,
            correlation,
        }
    })
}

fn classify_icmp_error(
    transport: Transport,
    request: &Packet,
    response: &Packet,
) -> Option<(Correlation, &'static str)> {
    let (request_source, _) = ip_tuple(request)?;
    let (_, response_destination) = ip_tuple(response)?;
    if request_source != response_destination {
        return None;
    }
    let layer = response
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "icmpv4" | "icmpv6"))?;
    let icmp_type = layer.field("type")?.as_u64()? as u8;
    let code = layer.field("code")?.as_u64()? as u8;
    let FieldValue::Bytes(body) = layer.field("body")? else {
        return None;
    };
    let quote = body.get(4..)?;
    if !quoted_probe_matches(transport, request, quote) {
        return None;
    }
    match layer.protocol_id().as_str() {
        "icmpv4" if icmp_type == 3 => match code {
            3 if transport == Transport::Udp => {
                Some((Correlation::PortUnreachable, "ICMPv4 port unreachable"))
            }
            9 | 10 | 13 => Some((
                Correlation::AdministrativelyProhibited,
                "ICMPv4 administratively prohibited",
            )),
            _ => Some((
                Correlation::DestinationUnreachable,
                "ICMPv4 destination unreachable",
            )),
        },
        "icmpv4" if icmp_type == 11 => Some((
            Correlation::TimeExceeded,
            "ICMPv4 time exceeded before reaching the endpoint",
        )),
        "icmpv6" if icmp_type == 1 => match code {
            4 if transport == Transport::Udp => {
                Some((Correlation::PortUnreachable, "ICMPv6 port unreachable"))
            }
            1 | 5 | 6 => Some((
                Correlation::AdministrativelyProhibited,
                "ICMPv6 policy or administrative rejection",
            )),
            _ => Some((
                Correlation::DestinationUnreachable,
                "ICMPv6 destination unreachable",
            )),
        },
        "icmpv6" if icmp_type == 3 => Some((
            Correlation::TimeExceeded,
            "ICMPv6 time exceeded before reaching the endpoint",
        )),
        _ => None,
    }
}

fn quoted_probe_matches(transport: Transport, request: &Packet, quote: &[u8]) -> bool {
    let Some(quoted) = parse_quoted_probe(quote) else {
        return false;
    };
    let Some((source, destination)) = ip_tuple(request) else {
        return false;
    };
    if quoted.source != source || quoted.destination != destination {
        return false;
    }
    match transport {
        Transport::Tcp | Transport::Udp => {
            let protocol = if transport == Transport::Tcp {
                ("tcp", 6)
            } else {
                ("udp", 17)
            };
            if quoted.protocol != protocol.1 {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == protocol.0)
            else {
                return false;
            };
            let Some(source_port) = layer.field("source_port").and_then(|value| value.as_u64())
            else {
                return false;
            };
            let Some(destination_port) = layer
                .field("destination_port")
                .and_then(|value| value.as_u64())
            else {
                return false;
            };
            if quoted.payload.get(..4)
                != Some(
                    &[
                        (source_port >> 8) as u8,
                        source_port as u8,
                        (destination_port >> 8) as u8,
                        destination_port as u8,
                    ][..],
                )
            {
                return false;
            }
            if transport == Transport::Tcp {
                let Some(sequence) = layer.field("sequence").and_then(|value| value.as_u64())
                else {
                    return false;
                };
                quoted.payload.get(4..8) == Some(&(sequence as u32).to_be_bytes()[..])
            } else {
                true
            }
        }
        Transport::Icmp => {
            let (protocol, name) = if source.is_ipv4() {
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
            let Some(icmp_type) = layer.field("type").and_then(|value| value.as_u64()) else {
                return false;
            };
            let Some(code) = layer.field("code").and_then(|value| value.as_u64()) else {
                return false;
            };
            let Some(FieldValue::Bytes(body)) = layer.field("body") else {
                return false;
            };
            quoted.payload.len() >= 8
                && quoted.payload[0] == icmp_type as u8
                && quoted.payload[1] == code as u8
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

fn ip_tuple(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
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
        Some((source, destination))
    })
}
