// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    codec::NetworkEnvelope,
    field::WireValue,
    layer::Layer,
    packet::Packet,
    protocol::BuiltinProtocol,
    protocol::semantics,
    protocol::transport::{Sctp, Tcp},
};

use super::{
    IcmpMessage,
    sctp::{sctp_cookie_echo, sctp_initiate_tag},
};
use crate::protocol::headers::{Ipv4Header, Ipv6Header};
use crate::protocol::network::{Ipv4, Ipv6, ip_protocol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpErrorKind {
    PortUnreachable,
    ProtocolUnreachable,
    AdministrativelyProhibited,
    DestinationUnreachable,
    TimeExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotedTransport {
    Tcp,
    Udp,
    Sctp,
    Icmp,
    Ip,
}

impl QuotedTransport {
    pub(super) fn of(protocol: BuiltinProtocol) -> Option<Self> {
        match protocol {
            BuiltinProtocol::Tcp => Some(Self::Tcp),
            BuiltinProtocol::Udp => Some(Self::Udp),
            BuiltinProtocol::Sctp => Some(Self::Sctp),
            BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6 => Some(Self::Icmp),
            _ => None,
        }
    }
}

/// Classifies `response` as an ICMP error about `request`.
pub fn quoted_icmp_error(
    request: &Packet,
    response: &Packet,
    expected_transport: QuotedTransport,
) -> Option<IcmpErrorKind> {
    let transport = request
        .iter()
        .find_map(|layer| BuiltinProtocol::of(layer).and_then(QuotedTransport::of))
        .or_else(|| {
            request
                .iter()
                .any(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip))
                .then_some(QuotedTransport::Ip)
        })?;
    if transport != expected_transport {
        return None;
    }
    let (icmp_protocol, layer) = directly_received_icmp(response)?;
    let icmp = IcmpMessage::of(layer)?;
    let (icmp_type, code) = (icmp.icmp_type, icmp.code);
    let body = icmp.body;
    let kind = match icmp_protocol {
        BuiltinProtocol::Icmpv4 if icmp_type == 3 => match code {
            2 if transport == QuotedTransport::Ip => IcmpErrorKind::ProtocolUnreachable,
            3 if transport == QuotedTransport::Udp => IcmpErrorKind::PortUnreachable,
            9 | 10 | 13 => IcmpErrorKind::AdministrativelyProhibited,
            _ => IcmpErrorKind::DestinationUnreachable,
        },
        BuiltinProtocol::Icmpv4 if icmp_type == 11 => IcmpErrorKind::TimeExceeded,
        BuiltinProtocol::Icmpv6 if icmp_type == 1 => match code {
            4 if transport == QuotedTransport::Udp => IcmpErrorKind::PortUnreachable,
            1 | 5 | 6 => IcmpErrorKind::AdministrativelyProhibited,
            _ => IcmpErrorKind::DestinationUnreachable,
        },
        BuiltinProtocol::Icmpv6 if icmp_type == 3 => IcmpErrorKind::TimeExceeded,
        BuiltinProtocol::Icmpv6
            if icmp_type == 4
                && code == 1
                && matches!(transport, QuotedTransport::Ip | QuotedTransport::Sctp)
                && ipv6_unrecognized_next_header_pointer_matches(body) =>
        {
            if transport == QuotedTransport::Ip {
                IcmpErrorKind::ProtocolUnreachable
            } else {
                IcmpErrorKind::DestinationUnreachable
            }
        }
        _ => return None,
    };
    let request_network = outer_network_envelope(request)?;
    let response_destination = outer_network_envelope(response)?.destination;
    if request_network.source != response_destination {
        return None;
    }
    if !quoted_probe_matches(transport, request, request_network, body.get(4..)?) {
        return None;
    }
    Some(kind)
}

/// Candidate discovery shares the exact validated quote walker used by the
/// authoritative matcher. A coarse protocol key covers header-only probes;
/// the optional transport key narrows ordinary TCP/UDP/SCTP/ICMP attempts.
pub(in crate::protocol) fn quoted_identity(
    response: &Packet,
) -> Option<(
    super::super::response_identity::Identity,
    Option<super::super::response_identity::Identity>,
)> {
    use super::super::response_identity::Identity;
    let (_, layer) = directly_received_icmp(response)?;
    let message = IcmpMessage::of(layer)?;
    let quote = parse_quoted_probe(message.body.get(4..)?, false)?;
    let protocol = Identity::IpProtocol {
        source: quote.source,
        destination: quote.destination,
        protocol: quote.protocol,
    };
    let transport = Identity::transport(
        quote.source,
        quote.destination,
        quote.protocol,
        quote.payload,
    );
    Some((protocol, transport))
}

fn directly_received_icmp(response: &Packet) -> Option<(BuiltinProtocol, &dyn Layer)> {
    let outer_scope = semantics::outer_scope_len(response);
    let (outer_network_index, outer_network_protocol) = response
        .iter()
        .take(outer_scope)
        .enumerate()
        .find_map(|(index, layer)| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some((index, protocol))
        })?;
    let (icmp_index, icmp_protocol, layer) = response
        .iter()
        .take(outer_scope)
        .enumerate()
        .find_map(|(index, layer)| {
            let protocol = BuiltinProtocol::of(layer)?;
            matches!(protocol, BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)
                .then_some((index, protocol, layer))
        })?;
    if icmp_index <= outer_network_index {
        return None;
    }
    let directly_nested = response
        .iter()
        .take(icmp_index)
        .skip(outer_network_index.saturating_add(1))
        .all(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension));
    if !directly_nested
        || !matches!(
            (outer_network_protocol, icmp_protocol),
            (BuiltinProtocol::Ipv4, BuiltinProtocol::Icmpv4)
                | (BuiltinProtocol::Ipv6, BuiltinProtocol::Icmpv6)
        )
    {
        return None;
    }
    Some((icmp_protocol, layer))
}

fn ipv6_unrecognized_next_header_pointer_matches(body: &[u8]) -> bool {
    let Some(pointer_bytes) = body.first_chunk::<4>() else {
        return false;
    };
    let pointer = usize::try_from(u32::from_be_bytes(*pointer_bytes)).ok();
    let Some(quote) = body.get(4..) else {
        return false;
    };
    if quote.len() == Ipv6Header::LENGTH
        && quote.first().is_some_and(|byte| byte >> 4 == 6)
        && quote.get(4..6) == Some(&[0, 0])
    {
        return pointer == Some(6);
    }
    let Ok(header) = Ipv6Header::walk_prefix(quote) else {
        return false;
    };
    let expected_offset = header
        .extensions()
        .last()
        .map_or(6, |extension| extension.range().start);
    pointer == Some(expected_offset)
}

fn quoted_probe_matches(
    transport: QuotedTransport,
    request: &Packet,
    network: NetworkEnvelope,
    quote: &[u8],
) -> bool {
    let Some(quoted) = parse_quoted_probe(quote, transport != QuotedTransport::Ip) else {
        return false;
    };
    if quoted.source != network.source || quoted.destination != network.destination {
        return false;
    }
    match transport {
        QuotedTransport::Tcp => {
            quoted_l4_layer(request, &quoted, BuiltinProtocol::Tcp, ip_protocol::TCP)
                .and_then(|(_, layer)| layer.downcast_ref::<Tcp>())
                .is_some_and(|tcp| {
                    quoted.payload.get(4..8) == Some(&tcp.sequence.to_be_bytes()[..])
                })
        }
        QuotedTransport::Udp => {
            quoted_l4_layer(request, &quoted, BuiltinProtocol::Udp, ip_protocol::UDP).is_some()
        }
        QuotedTransport::Sctp => {
            let Some((index, layer)) =
                quoted_l4_layer(request, &quoted, BuiltinProtocol::Sctp, ip_protocol::SCTP)
            else {
                return false;
            };
            let Some(sctp) = layer.downcast_ref::<Sctp>() else {
                return false;
            };
            quoted.payload.get(4..8) == Some(&sctp.verification_tag.to_be_bytes()[..])
                && quoted_sctp_matches(sctp, request, index, quoted.payload)
        }
        QuotedTransport::Icmp => quoted_icmp_matches(request, network, &quoted),
        QuotedTransport::Ip => quoted_ip_matches(request, &quoted),
    }
}

fn quoted_l4_layer<'a>(
    request: &'a Packet,
    quoted: &QuotedProbe<'_>,
    protocol: BuiltinProtocol,
    protocol_number: u8,
) -> Option<(usize, &'a dyn Layer)> {
    if quoted.protocol != protocol_number {
        return None;
    }
    let (layer_index, layer) = request
        .iter()
        .enumerate()
        .find(|(_, layer)| BuiltinProtocol::of(*layer) == Some(protocol))?;
    let key = semantics::transport_key(layer)?;
    let source_port = key.source_port.to_be_bytes();
    let destination_port = key.destination_port.to_be_bytes();
    let ports = [
        source_port[0],
        source_port[1],
        destination_port[0],
        destination_port[1],
    ];
    (quoted.payload.get(..4) == Some(&ports[..])).then_some((layer_index, layer))
}

fn quoted_icmp_matches(
    request: &Packet,
    network: NetworkEnvelope,
    quoted: &QuotedProbe<'_>,
) -> bool {
    let (protocol_number, protocol) = if network.source.is_ipv4() {
        (ip_protocol::ICMPV4, BuiltinProtocol::Icmpv4)
    } else {
        (ip_protocol::ICMPV6, BuiltinProtocol::Icmpv6)
    };
    if quoted.protocol != protocol_number {
        return false;
    }
    let Some(layer) = request
        .iter()
        .find(|layer| BuiltinProtocol::of(*layer) == Some(protocol))
    else {
        return false;
    };
    let Some(IcmpMessage {
        icmp_type,
        code,
        body,
    }) = IcmpMessage::of(layer)
    else {
        return false;
    };
    let Some(quoted_echo) = quoted.payload.first_chunk::<8>() else {
        return false;
    };
    let Some(body_identity) = body.first_chunk::<4>() else {
        return false;
    };
    quoted_echo[0] == icmp_type && quoted_echo[1] == code && quoted_echo[4..8] == body_identity[..]
}

fn quoted_sctp_matches(sctp: &Sctp, request: &Packet, sctp_index: usize, payload: &[u8]) -> bool {
    let Some(checksum_bytes) = sctp_checksum_bytes(sctp) else {
        return false;
    };
    if sctp.verification_tag == 0 {
        let Some((_, chunk)) = sctp_initiate_tag(request, sctp_index, 1) else {
            return false;
        };
        payload.get(8..12) == Some(&checksum_bytes[..]) && payload.get(12..20) == chunk.get(..8)
    } else {
        let Some(chunk) = sctp_cookie_echo(request, sctp_index) else {
            return false;
        };
        if let Some(quoted_checksum) = payload.get(8..12) {
            if quoted_checksum != checksum_bytes {
                return false;
            }
        } else if payload.len() != MIN_QUOTED_TRANSPORT_LEN {
            return false;
        }
        if let Some(quoted_chunk) = payload.get(12..)
            && !quoted_chunk.is_empty()
        {
            chunk.get(..quoted_chunk.len()) == Some(quoted_chunk)
        } else {
            true
        }
    }
}

fn sctp_checksum_bytes(sctp: &Sctp) -> Option<[u8; 4]> {
    match &sctp.checksum {
        WireValue::Exact(value) => Some(value.to_le_bytes()),
        WireValue::Raw(value) => <[u8; 4]>::try_from(value.as_ref()).ok(),
        WireValue::Auto => None,
    }
}

fn quoted_ip_matches(request: &Packet, quoted: &QuotedProbe<'_>) -> bool {
    if !quoted.payload.is_empty() || quoted.declared_payload_len != 0 {
        return false;
    }
    match quoted.source {
        IpAddr::V4(_) => request.get::<Ipv4>().is_some_and(|ipv4| {
            ipv4.protocol == WireValue::Exact(quoted.protocol)
                && quoted.ipv4_identification == Some(ipv4.identification)
        }),
        IpAddr::V6(_) => request.get::<Ipv6>().is_some_and(|ipv6| {
            ipv6.next_header == WireValue::Exact(quoted.protocol)
                && quoted.ipv6_flow_label == Some(ipv6.flow_label)
        }),
    }
}

struct QuotedProbe<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ipv4_identification: Option<u16>,
    ipv6_flow_label: Option<u32>,
    declared_payload_len: usize,
    payload: &'a [u8],
}

const MIN_QUOTED_TRANSPORT_LEN: usize = 8;
const MAX_QUOTED_IPV6_EXTENSION_HEADERS: usize = 16;

fn parse_quoted_probe(bytes: &[u8], require_transport: bool) -> Option<QuotedProbe<'_>> {
    let min_payload = if require_transport {
        MIN_QUOTED_TRANSPORT_LEN
    } else {
        0
    };
    match bytes.first()? >> 4 {
        4 => {
            let header = Ipv4Header::walk_prefix(bytes).ok()?;
            let header_len = header.header_length();
            // Only atomic and first fragments can quote a transport key at
            // the start of this payload.
            if header.flags_and_offset() & 0x1fff != 0
                || bytes.len() < header_len + min_payload
                || header.total_length() < header_len + min_payload
            {
                return None;
            }
            let identification = u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]);
            Some(QuotedProbe {
                source: IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&bytes[Ipv4Header::SOURCE]).ok()?,
                )),
                destination: IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&bytes[Ipv4Header::DESTINATION]).ok()?,
                )),
                protocol: header.protocol(),
                ipv4_identification: Some(identification),
                ipv6_flow_label: None,
                declared_payload_len: header.total_length().saturating_sub(header_len),
                payload: bytes.get(header_len..header.total_length().min(bytes.len()))?,
            })
        }
        6 => {
            if !require_transport
                && bytes.len() >= Ipv6Header::LENGTH
                && bytes.get(4..6) == Some(&[0, 0])
            {
                // The declared empty datagram ends at the base header. RFC
                // 4884 padding and ICMP extensions belong to the error, not
                // the quoted packet (and must not imply a jumbogram).
                let first = u32::from_be_bytes(<[u8; 4]>::try_from(bytes.get(..4)?).ok()?);
                return Some(QuotedProbe {
                    source: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&bytes[Ipv6Header::SOURCE]).ok()?,
                    )),
                    destination: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&bytes[Ipv6Header::DESTINATION]).ok()?,
                    )),
                    protocol: *bytes.get(6)?,
                    ipv4_identification: None,
                    ipv6_flow_label: Some(first & 0x000f_ffff),
                    declared_payload_len: 0,
                    payload: &[],
                });
            }
            let header = Ipv6Header::walk_prefix(bytes).ok()?;
            let end = header.datagram_length().min(bytes.len());
            // Only atomic and first fragments can quote a transport key at
            // the start of this payload.
            if header.extensions().len() > MAX_QUOTED_IPV6_EXTENSION_HEADERS
                || header.extensions().iter().any(|extension| {
                    extension
                        .fragment_offset_and_flags()
                        .is_some_and(|word| word & 0xfffe != 0)
                })
            {
                return None;
            }
            let (protocol, offset) = header.upper_layer();
            if end < offset
                || end - offset < min_payload
                || header.datagram_length() < offset + min_payload
            {
                return None;
            }
            let first = u32::from_be_bytes(<[u8; 4]>::try_from(bytes.get(..4)?).ok()?);
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[Ipv6Header::SOURCE]).ok()?,
                )),
                destination: IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[Ipv6Header::DESTINATION]).ok()?,
                )),
                protocol,
                ipv4_identification: None,
                ipv6_flow_label: Some(first & 0x000f_ffff),
                declared_payload_len: header.datagram_length().saturating_sub(offset),
                payload: bytes.get(offset..end)?,
            })
        }
        _ => None,
    }
}

fn outer_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = semantics::outer_ip_path(packet).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.header_destination,
    })
}
