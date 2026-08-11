// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    Packet,
    codec::NetworkEnvelope,
    field::FieldValue,
    layer::Layer,
    semantics::{self, BuiltinProtocol},
};

use super::{sctp::sctp_initiate_tag, unsigned_field};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotedIcmpError {
    PortUnreachable,
    AdministrativelyProhibited,
    DestinationUnreachable,
    TimeExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotedProbeTransport {
    Tcp,
    Udp,
    Sctp,
    Icmp,
}

/// Identifies an ICMP error that quotes the exact request. The client exchange
/// uses this protocol-layer correlation before workflow-specific classification
/// so it can retain the capture ingress latency.
pub fn quoted_icmp_error_kind(
    request: &Packet,
    response: &Packet,
    expected_transport: QuotedProbeTransport,
) -> Option<QuotedIcmpError> {
    let transport = request
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Tcp) => Some(QuotedProbeTransport::Tcp),
            Some(BuiltinProtocol::Udp) => Some(QuotedProbeTransport::Udp),
            Some(BuiltinProtocol::Sctp) => Some(QuotedProbeTransport::Sctp),
            Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => {
                Some(QuotedProbeTransport::Icmp)
            }
            _ => None,
        })?;
    if transport != expected_transport {
        return None;
    }
    let (icmp_protocol, layer) = directly_received_icmp(response)?;
    let icmp_type = unsigned_field::<u8>(layer, "type")?;
    let code = unsigned_field::<u8>(layer, "code")?;
    let kind = match icmp_protocol {
        BuiltinProtocol::Icmpv4 if icmp_type == 3 => match code {
            3 if transport == QuotedProbeTransport::Udp => QuotedIcmpError::PortUnreachable,
            9 | 10 | 13 => QuotedIcmpError::AdministrativelyProhibited,
            _ => QuotedIcmpError::DestinationUnreachable,
        },
        BuiltinProtocol::Icmpv4 if icmp_type == 11 => QuotedIcmpError::TimeExceeded,
        BuiltinProtocol::Icmpv6 if icmp_type == 1 => match code {
            4 if transport == QuotedProbeTransport::Udp => QuotedIcmpError::PortUnreachable,
            1 | 5 | 6 => QuotedIcmpError::AdministrativelyProhibited,
            _ => QuotedIcmpError::DestinationUnreachable,
        },
        BuiltinProtocol::Icmpv6 if icmp_type == 3 => QuotedIcmpError::TimeExceeded,
        _ => return None,
    };
    let FieldValue::Bytes(body) = layer.field("body")? else {
        return None;
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
        .skip(outer_network_index + 1)
        .take(icmp_index - outer_network_index - 1)
        .all(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension));
    if !directly_nested {
        return None;
    }
    let enclosing_network_index = response
        .iter()
        .enumerate()
        .take(icmp_index)
        .rev()
        .find_map(|(index, layer)| {
            BuiltinProtocol::of(layer)
                .is_some_and(BuiltinProtocol::is_ip)
                .then_some(index)
        })?;
    if enclosing_network_index != outer_network_index
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

fn quoted_probe_matches(
    transport: QuotedProbeTransport,
    request: &Packet,
    network: NetworkEnvelope,
    quote: &[u8],
) -> bool {
    let Some(quoted) = parse_quoted_probe(quote) else {
        return false;
    };
    if quoted.source != network.source || quoted.destination != network.destination {
        return false;
    }
    match transport {
        QuotedProbeTransport::Tcp | QuotedProbeTransport::Udp | QuotedProbeTransport::Sctp => {
            let (protocol, protocol_number) = match transport {
                QuotedProbeTransport::Tcp => (BuiltinProtocol::Tcp, 6),
                QuotedProbeTransport::Udp => (BuiltinProtocol::Udp, 17),
                QuotedProbeTransport::Sctp => (BuiltinProtocol::Sctp, 132),
                QuotedProbeTransport::Icmp => unreachable!("ICMP uses the other match arm"),
            };
            if quoted.protocol != protocol_number {
                return false;
            }
            let Some((layer_index, layer)) = request
                .iter()
                .enumerate()
                .find(|(_, layer)| BuiltinProtocol::of(*layer) == Some(protocol))
            else {
                return false;
            };
            let Some(key) = semantics::transport_key(layer) else {
                return false;
            };
            let source_port = key.source_port.to_be_bytes();
            let destination_port = key.destination_port.to_be_bytes();
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
            match transport {
                QuotedProbeTransport::Tcp => {
                    let Some(sequence) = unsigned_field::<u32>(layer, "sequence") else {
                        return false;
                    };
                    quoted.payload.get(4..8) == Some(&sequence.to_be_bytes()[..])
                }
                QuotedProbeTransport::Sctp => {
                    let Some(verification_tag) = unsigned_field::<u32>(layer, "verification_tag")
                    else {
                        return false;
                    };
                    quoted.payload.get(4..8) == Some(&verification_tag.to_be_bytes()[..])
                        && quoted_sctp_init_matches(layer, request, layer_index, quoted.payload)
                }
                QuotedProbeTransport::Udp => true,
                QuotedProbeTransport::Icmp => unreachable!("ICMP uses the other match arm"),
            }
        }
        QuotedProbeTransport::Icmp => {
            let (protocol_number, protocol) = if network.source.is_ipv4() {
                (1, BuiltinProtocol::Icmpv4)
            } else {
                (58, BuiltinProtocol::Icmpv6)
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
            let Some(icmp_type) = unsigned_field::<u8>(layer, "type") else {
                return false;
            };
            let Some(code) = unsigned_field::<u8>(layer, "code") else {
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

fn quoted_sctp_init_matches(
    layer: &dyn crate::layer::Layer,
    request: &Packet,
    sctp_index: usize,
    payload: &[u8],
) -> bool {
    let Some((_, chunk)) = sctp_initiate_tag(request, sctp_index, 1) else {
        return false;
    };
    let Some(checksum) = layer.field("checksum") else {
        return false;
    };
    let checksum_bytes = match checksum {
        FieldValue::Unsigned(value) => {
            let Ok(value) = u32::try_from(value) else {
                return false;
            };
            value.to_le_bytes()
        }
        FieldValue::Bytes(value) => {
            let Ok(value) = <[u8; 4]>::try_from(value.as_ref()) else {
                return false;
            };
            value
        }
        _ => return false,
    };
    payload.get(8..12) == Some(&checksum_bytes[..]) && payload.get(12..20) == chunk.get(..8)
}

struct QuotedProbe<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

const IPV6_HEADER_LEN: usize = 40;
const MIN_QUOTED_TRANSPORT_LEN: usize = 8;
const MAX_QUOTED_IPV6_EXTENSION_HEADERS: usize = 16;

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
            let total_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if total_length < header_len + 8 {
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
                payload: &bytes[header_len..total_length.min(bytes.len())],
            })
        }
        6 => {
            if bytes.len() < IPV6_HEADER_LEN {
                return None;
            }
            let payload_length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            let end = IPV6_HEADER_LEN
                .checked_add(payload_length)?
                .min(bytes.len());
            let (protocol, payload) = parse_quoted_ipv6_payload(bytes, bytes[6], end)?;
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                protocol,
                payload,
            })
        }
        _ => None,
    }
}

fn parse_quoted_ipv6_payload(bytes: &[u8], mut protocol: u8, end: usize) -> Option<(u8, &[u8])> {
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0_usize;
    loop {
        let header = bytes.get(offset..end)?;
        let header_len = match protocol {
            // Hop-by-Hop Options, Routing, and Destination Options.
            0 | 43 | 60 => {
                if extension_count >= MAX_QUOTED_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                let next = *header.first()?;
                let header_len = (usize::from(*header.get(1)?) + 1).checked_mul(8)?;
                if header_len < 8 || header.len() < header_len {
                    return None;
                }
                protocol = next;
                header_len
            }
            // Fragment. Only atomic and first fragments can quote a transport
            // key at the start of this payload.
            44 => {
                if extension_count >= MAX_QUOTED_IPV6_EXTENSION_HEADERS || header.len() < 8 {
                    return None;
                }
                let offset_and_flags = u16::from_be_bytes([header[2], header[3]]);
                if offset_and_flags & 0xfffe != 0 {
                    return None;
                }
                protocol = header[0];
                8
            }
            // Authentication Header. Its length is measured in 32-bit words
            // excluding the first two words.
            51 => {
                if extension_count >= MAX_QUOTED_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                let next = *header.first()?;
                let header_len = (usize::from(*header.get(1)?) + 2).checked_mul(4)?;
                if header_len < 12 || header.len() < header_len {
                    return None;
                }
                protocol = next;
                header_len
            }
            _ => break,
        };
        offset = offset.checked_add(header_len)?;
        extension_count += 1;
    }
    if end.checked_sub(offset)? < MIN_QUOTED_TRANSPORT_LEN {
        return None;
    }
    Some((protocol, bytes.get(offset..end)?))
}

fn outer_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = semantics::outer_ip_path(packet).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.header_destination,
    })
}
