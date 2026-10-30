// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checksum repairs derived from field edits, applied innermost first.

use std::collections::BTreeMap;

use super::{ChangeOrigin, FieldChange, builtin, occurrence_of, read_uint};
use crate::decode::DecodedPacket;
use crate::layout::{ByteRange, PacketLayout};
use crate::protocol::{BuiltinProtocol, checksum_parts, headers::IpHeader};
use crate::transform::{Error, InvalidInput, Unsupported};

pub(super) fn collect_repairs(
    decoded: &DecodedPacket,
    target: usize,
    range: ByteRange,
    bytes: &[u8],
    repairs: &mut BTreeMap<usize, Repair>,
) -> Result<(), Error> {
    let layout = &decoded.layout;
    match builtin(decoded, target) {
        Some(BuiltinProtocol::Ipv4) => {
            repairs.insert(target, Repair::Ipv4Header(target));
        }
        Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
            repairs.insert(target, Repair::Transport(target));
        }
        Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => {
            repairs.insert(target, Repair::Icmp(target));
        }
        _ => refuse_unrepairable(&layout.layers[target])?,
    }
    for ancestor in &layout.layers[..target] {
        match builtin(decoded, ancestor.index) {
            // An IPv4 header checksum covers only the header itself, never a
            // descendant layer's bytes; IPv6 has no checksum field at all.
            Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6) => {}
            Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
                let index = ancestor.index;
                let span = transport_span(decoded, index, bytes)?;
                if range.start < span.start || range.end > span.end {
                    return Err(Error::Invalid(InvalidInput::EditOutsideTransport));
                }
                repairs.insert(index, Repair::Transport(index));
            }
            _ => refuse_unrepairable(ancestor)?,
        }
    }
    Ok(())
}

fn refuse_unrepairable(layer: &crate::layout::LayerLayout) -> Result<(), Error> {
    if layer.fields.iter().any(|field| field.name == "checksum") {
        return Err(Error::Unsupported(Unsupported::EditChecksumCoverage));
    }
    Ok(())
}

fn enclosing_network(decoded: &DecodedPacket, layer: usize) -> Result<usize, Error> {
    (0..layer)
        .rev()
        .find(|index| builtin(decoded, *index).is_some_and(BuiltinProtocol::is_ip))
        .ok_or(Error::Unsupported(Unsupported::TransportChecksumEnvelope))
}

fn network_end(layout: &PacketLayout, network: usize, bytes: &[u8]) -> Result<usize, Error> {
    let (start, header) = walk_network(layout, network, bytes)?;
    Ok(start + header.datagram_length())
}

fn walk_network(
    layout: &PacketLayout,
    network: usize,
    bytes: &[u8],
) -> Result<(usize, IpHeader), Error> {
    let start = layout.layers[network].range.start;
    let ip = bytes
        .get(start..)
        .ok_or(Error::Invalid(InvalidInput::TransportCoverage))?;
    Ok((start, IpHeader::walk(ip)?))
}

fn transport_span(
    decoded: &DecodedPacket,
    transport: usize,
    bytes: &[u8],
) -> Result<ByteRange, Error> {
    let layout = &decoded.layout;
    let layer = &layout.layers[transport];
    let network = enclosing_network(decoded, transport)?;
    let end_of_payload = network_end(layout, network, bytes)?;
    let start = layer.range.start;
    if start < layout.layers[network].range.end || end_of_payload > bytes.len() {
        return Err(Error::Invalid(InvalidInput::TransportCoverage));
    }
    let end = match builtin(decoded, transport) {
        Some(BuiltinProtocol::Udp) => {
            let length = read_uint(bytes, ByteRange::new(start + 4, start + 6))?;
            if length < 8 {
                return Err(Error::Invalid(InvalidInput::UdpLength));
            }
            let end = start
                .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
                .ok_or(Error::Invalid(InvalidInput::UdpLengthOverflow))?;
            if end > end_of_payload {
                return Err(Error::Invalid(InvalidInput::UdpLengthExceedsPayload));
            }
            end
        }
        Some(BuiltinProtocol::Tcp | BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => {
            end_of_payload
        }
        _ => return Err(Error::Unsupported(Unsupported::TransportChecksum)),
    };
    Ok(ByteRange::new(start, end))
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Repair {
    Ipv4Header(usize),
    Transport(usize),
    Icmp(usize),
}

impl Repair {
    pub(super) fn run(
        &self,
        bytes: &mut [u8],
        decoded: &DecodedPacket,
    ) -> Result<Option<FieldChange>, Error> {
        match *self {
            Self::Ipv4Header(layer) => repair_ipv4(bytes, &decoded.layout, layer),
            Self::Transport(layer) => repair_transport(bytes, decoded, layer),
            Self::Icmp(layer) => repair_icmp(bytes, decoded, layer),
        }
    }
}

fn checksum_field_range(layout: &PacketLayout, layer: usize) -> Result<ByteRange, Error> {
    layout.layers[layer]
        .fields
        .iter()
        .find(|field| field.name == "checksum")
        .map(|field| field.range)
        .filter(|range| range.end - range.start == 2)
        .ok_or(Error::Unsupported(Unsupported::ChecksumLayout))
}

fn repair_ipv4(
    bytes: &mut [u8],
    layout: &PacketLayout,
    layer: usize,
) -> Result<Option<FieldChange>, Error> {
    let header = layout.layers[layer].range;
    let checksum_range = checksum_field_range(layout, layer)?;
    if checksum_range.end > header.end || checksum_range.start < header.start {
        return Err(Error::Invalid(InvalidInput::Ipv4ChecksumPlacement));
    }
    let old = read_uint(bytes, checksum_range)?;
    bytes[checksum_range.start..checksum_range.end].fill(0);
    let value = checksum_parts(&[&bytes[header.start..header.end]]);
    bytes[checksum_range.start..checksum_range.end].copy_from_slice(&value.to_be_bytes());
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!("ipv4#{}.checksum", occurrence_of(layout, layer)),
        layer,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}

fn repair_transport(
    bytes: &mut [u8],
    decoded: &DecodedPacket,
    transport: usize,
) -> Result<Option<FieldChange>, Error> {
    let layout = &decoded.layout;
    let layer = &layout.layers[transport];
    let network = enclosing_network(decoded, transport)?;
    let (network_start, header) = walk_network(layout, network, bytes)?;
    crate::transform::ensure_checksum_coverage(&bytes[network_start..], &header)?;
    let span = transport_span(decoded, transport, bytes)?;
    let checksum_range = checksum_field_range(layout, transport)?;
    if checksum_range.end > span.end || checksum_range.start < span.start {
        return Err(Error::Invalid(InvalidInput::TransportChecksumPlacement));
    }
    let udp = builtin(decoded, transport) == Some(BuiltinProtocol::Udp);
    let old = read_uint(bytes, checksum_range)?;
    let (protocol, name) = if udp {
        (crate::protocol::network::ip_protocol::UDP, "udp")
    } else {
        (crate::protocol::network::ip_protocol::TCP, "tcp")
    };
    let addresses = header.addresses(&bytes[network_start..])?;
    let Some(value) = crate::transform::repair_checksum(
        &mut bytes[span.start..span.end],
        checksum_range.start - span.start..checksum_range.end - span.start,
        protocol,
        name,
        addresses,
    )?
    else {
        return Ok(None);
    };
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!(
            "{}#{}.checksum",
            layer.protocol.as_str(),
            occurrence_of(layout, transport)
        ),
        layer: transport,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}

/// ICMPv4 covers only its message; ICMPv6 adds the IPv6 pseudo-header, so the
/// message must sit in its own address family.
fn repair_icmp(
    bytes: &mut [u8],
    decoded: &DecodedPacket,
    layer: usize,
) -> Result<Option<FieldChange>, Error> {
    let layout = &decoded.layout;
    let network = enclosing_network(decoded, layer)?;
    let (network_start, header) = walk_network(layout, network, bytes)?;
    crate::transform::ensure_checksum_coverage(&bytes[network_start..], &header)?;
    let span = transport_span(decoded, layer, bytes)?;
    let checksum_range = checksum_field_range(layout, layer)?;
    if checksum_range.end > span.end || checksum_range.start < span.start {
        return Err(Error::Invalid(InvalidInput::TransportChecksumPlacement));
    }
    let old = read_uint(bytes, checksum_range)?;
    let value = match (builtin(decoded, layer), &header) {
        (Some(BuiltinProtocol::Icmpv4), IpHeader::V4(_)) => {
            bytes[checksum_range.start..checksum_range.end].fill(0);
            let value = checksum_parts(&[&bytes[span.start..span.end]]);
            bytes[checksum_range.start..checksum_range.end].copy_from_slice(&value.to_be_bytes());
            value
        }
        (Some(BuiltinProtocol::Icmpv6), IpHeader::V6(_)) => {
            let addresses = header.addresses(&bytes[network_start..])?;
            crate::transform::repair_checksum(
                &mut bytes[span.start..span.end],
                checksum_range.start - span.start..checksum_range.end - span.start,
                crate::protocol::network::ip_protocol::ICMPV6,
                BuiltinProtocol::Icmpv6.as_str(),
                addresses,
            )?
            .ok_or(Error::Unsupported(Unsupported::ChecksumLayout))?
        }
        _ => return Err(Error::Unsupported(Unsupported::TransportChecksumEnvelope)),
    };
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!(
            "{}#{}.checksum",
            layout.layers[layer].protocol.as_str(),
            occurrence_of(layout, layer)
        ),
        layer,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}
