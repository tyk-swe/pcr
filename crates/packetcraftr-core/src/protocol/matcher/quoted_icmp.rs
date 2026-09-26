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

use super::{IcmpMessage, sctp::sctp_initiate_tag};
use crate::protocol::network::ip_protocol;

/// What an ICMPv4 or ICMPv6 error message that quotes a request reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// Port unreachable for a UDP request (ICMPv4 3/3, ICMPv6 1/4).
    PortUnreachable,
    /// Communication administratively prohibited (ICMPv4 3/9, 3/10, 3/13;
    /// ICMPv6 1/1, 1/5, 1/6).
    AdministrativelyProhibited,
    /// Any other destination-unreachable code, including port unreachable for
    /// a transport other than UDP.
    DestinationUnreachable,
    /// Time exceeded (ICMPv4 11, ICMPv6 3).
    TimeExceeded,
}

/// The transport a request carries, which the quoted copy inside an ICMP
/// error must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotedTransport {
    Tcp,
    Udp,
    Sctp,
    /// ICMPv4 or ICMPv6, matched by echo identifier and sequence.
    Icmp,
}

/// Classifies `response` as an ICMP error about `request`.
///
/// Returns `None` unless the request's first transport is
/// `expected_transport`, the response's outer IP layer directly carries an
/// ICMP error of the same IP version addressed to the request's source, and
/// the quoted datagram is the request's own outer network header and
/// transport key. A live exchange uses this before its own classification, so
/// the evidence keeps the time the response arrived.
pub fn quoted_icmp_error(
    request: &Packet,
    response: &Packet,
    expected_transport: QuotedTransport,
) -> Option<IcmpErrorKind> {
    let transport = request
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Tcp) => Some(QuotedTransport::Tcp),
            Some(BuiltinProtocol::Udp) => Some(QuotedTransport::Udp),
            Some(BuiltinProtocol::Sctp) => Some(QuotedTransport::Sctp),
            Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => Some(QuotedTransport::Icmp),
            _ => None,
        })?;
    if transport != expected_transport {
        return None;
    }
    let (icmp_protocol, layer) = directly_received_icmp(response)?;
    let icmp = IcmpMessage::of(layer)?;
    let (icmp_type, code) = (icmp.icmp_type, icmp.code);
    let kind = match icmp_protocol {
        BuiltinProtocol::Icmpv4 if icmp_type == 3 => match code {
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
        _ => return None,
    };
    let body = icmp.body;
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
    let nested_start = outer_network_index.checked_add(1)?;
    let nested_len = icmp_index.checked_sub(nested_start)?;
    let directly_nested = response
        .iter()
        .skip(nested_start)
        .take(nested_len)
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
    transport: QuotedTransport,
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
        QuotedTransport::Tcp | QuotedTransport::Udp | QuotedTransport::Sctp => {
            let (protocol, protocol_number) = match transport {
                QuotedTransport::Tcp => (BuiltinProtocol::Tcp, ip_protocol::TCP),
                QuotedTransport::Udp => (BuiltinProtocol::Udp, ip_protocol::UDP),
                QuotedTransport::Sctp => (BuiltinProtocol::Sctp, 132),
                QuotedTransport::Icmp => unreachable!("ICMP uses the other match arm"),
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
                QuotedTransport::Tcp => {
                    let Some(tcp) = layer.downcast_ref::<Tcp>() else {
                        return false;
                    };
                    quoted.payload.get(4..8) == Some(&tcp.sequence.to_be_bytes()[..])
                }
                QuotedTransport::Sctp => {
                    let Some(sctp) = layer.downcast_ref::<Sctp>() else {
                        return false;
                    };
                    quoted.payload.get(4..8) == Some(&sctp.verification_tag.to_be_bytes()[..])
                        && quoted_sctp_init_matches(sctp, request, layer_index, quoted.payload)
                }
                QuotedTransport::Udp => true,
                QuotedTransport::Icmp => unreachable!("ICMP uses the other match arm"),
            }
        }
        QuotedTransport::Icmp => {
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
            quoted_echo[0] == icmp_type
                && quoted_echo[1] == code
                && quoted_echo[4..8] == body_identity[..]
        }
    }
}

fn quoted_sctp_init_matches(
    sctp: &Sctp,
    request: &Packet,
    sctp_index: usize,
    payload: &[u8],
) -> bool {
    let Some((_, chunk)) = sctp_initiate_tag(request, sctp_index, 1) else {
        return false;
    };
    let checksum_bytes = match &sctp.checksum {
        WireValue::Exact(value) => value.to_le_bytes(),
        WireValue::Raw(value) => {
            let Ok(value) = <[u8; 4]>::try_from(value.as_ref()) else {
                return false;
            };
            value
        }
        WireValue::Auto => return false,
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
            let header = bytes.first_chunk::<20>()?;
            let header_len = usize::from(header[0] & 0x0f).checked_mul(4)?;
            let minimum_len = header_len.checked_add(8)?;
            if header_len < 20 || bytes.len() < minimum_len {
                return None;
            }
            let total_length = usize::from(u16::from_be_bytes([header[2], header[3]]));
            if total_length < minimum_len {
                return None;
            }
            let fragment_offset = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V4(Ipv4Addr::new(
                    header[12], header[13], header[14], header[15],
                )),
                destination: IpAddr::V4(Ipv4Addr::new(
                    header[16], header[17], header[18], header[19],
                )),
                protocol: header[9],
                payload: bytes.get(header_len..total_length.min(bytes.len()))?,
            })
        }
        6 => {
            let header = bytes.first_chunk::<IPV6_HEADER_LEN>()?;
            let payload_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            let end = IPV6_HEADER_LEN
                .checked_add(payload_length)?
                .min(bytes.len());
            let (protocol, payload) = parse_quoted_ipv6_payload(bytes, header[6], end)?;
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&header[24..40]).ok()?,
                )),
                protocol,
                payload,
            })
        }
        _ => None,
    }
}

fn extension_len(header: &[u8], addend: usize, unit: usize, minimum: usize) -> Option<(u8, usize)> {
    let next = *header.first()?;
    let header_len = usize::from(*header.get(1)?)
        .checked_add(addend)?
        .checked_mul(unit)?;
    if header_len < minimum || header.len() < header_len {
        return None;
    }
    Some((next, header_len))
}

fn parse_quoted_ipv6_payload(bytes: &[u8], mut protocol: u8, end: usize) -> Option<(u8, &[u8])> {
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0_usize;
    loop {
        let header = bytes.get(offset..end)?;
        let header_len = match protocol {
            ip_protocol::HOP_BY_HOP | ip_protocol::ROUTING | ip_protocol::DESTINATION_OPTIONS => {
                let (next, header_len) = extension_len(header, 1, 8, 8)?;
                protocol = next;
                header_len
            }
            // Only atomic and first fragments can quote a transport key at the
            // start of this payload.
            ip_protocol::FRAGMENT => {
                let fragment = header.first_chunk::<8>()?;
                let offset_and_flags = u16::from_be_bytes([fragment[2], fragment[3]]);
                if offset_and_flags & 0xfffe != 0 {
                    return None;
                }
                protocol = fragment[0];
                8
            }
            // The AH length is measured in 32-bit words excluding the first
            // two words.
            ip_protocol::AH => {
                let (next, header_len) = extension_len(header, 2, 4, 12)?;
                protocol = next;
                header_len
            }
            _ => break,
        };
        offset = offset.checked_add(header_len)?;
        extension_count = extension_count.checked_add(1)?;
        if extension_count > MAX_QUOTED_IPV6_EXTENSION_HEADERS {
            return None;
        }
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
