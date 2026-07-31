// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr_capture::LinkType;

use super::{ipv4_source_route_destinations, validate_segment_route};
use crate::build::DEFAULT_MAX_LAYERS;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;

/// Policy-relevant destinations recovered from exact final wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireDestinations {
    /// The supported link envelope does not carry an IP route.
    NoRoute,
    /// Every destination declared by the IP header and supported source route.
    Destinations(Vec<IpAddr>),
    /// Declared IP bytes cannot be authorized without guessing.
    MalformedOrAmbiguous { reason: String },
}

/// Strictly interprets route-bearing fields in exact final wire bytes.
pub fn final_wire_destinations(link_type: LinkType, bytes: &[u8]) -> WireDestinations {
    match parse_wire_destinations(link_type, bytes) {
        Ok(None) => WireDestinations::NoRoute,
        Ok(Some(destinations)) => WireDestinations::Destinations(destinations),
        Err(reason) => WireDestinations::MalformedOrAmbiguous { reason },
    }
}

fn parse_wire_destinations(
    link_type: LinkType,
    bytes: &[u8],
) -> Result<Option<Vec<IpAddr>>, String> {
    let (network_offset, version) = match link_type {
        LinkType::BSD_RAW | LinkType::RAW => {
            let version = bytes
                .first()
                .map(|byte| byte >> 4)
                .ok_or_else(|| "raw IP frame is empty".to_owned())?;
            if !matches!(version, 4 | 6) {
                return Err(format!(
                    "raw frame declares unsupported IP version {version}"
                ));
            }
            (0, version)
        }
        LinkType::IPV4 => (0, 4),
        LinkType::IPV6 => (0, 6),
        LinkType::ETHERNET => ethernet_network(bytes)?,
        _ => return Ok(None),
    };
    match version {
        0 => Ok(None),
        4 => collect_ipv4_destinations(bytes, network_offset).map(Some),
        6 => collect_ipv6_destinations(bytes, network_offset).map(Some),
        _ => Err(format!("unsupported IP version {version}")),
    }
}

fn ethernet_network(bytes: &[u8]) -> Result<(usize, u8), String> {
    if bytes.len() < ETHERNET_HEADER_LEN {
        return Err("Ethernet frame is truncated".to_owned());
    }
    let mut offset = ETHERNET_HEADER_LEN;
    let mut ether_type =
        read_u16(bytes, 12).ok_or_else(|| "Ethernet EtherType is truncated".to_owned())?;
    let mut remaining = DEFAULT_MAX_LAYERS;
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_SERVICE_VLAN) {
        if remaining == 0 {
            return Err("Ethernet VLAN chain exceeds the layer limit".to_owned());
        }
        remaining -= 1;
        let next_type_offset = offset
            .checked_add(2)
            .ok_or_else(|| "Ethernet VLAN offset overflowed".to_owned())?;
        ether_type = read_u16(bytes, next_type_offset)
            .ok_or_else(|| "Ethernet VLAN header is truncated".to_owned())?;
        offset = offset
            .checked_add(VLAN_HEADER_LEN)
            .ok_or_else(|| "Ethernet VLAN offset overflowed".to_owned())?;
    }
    Ok((
        offset,
        match ether_type {
            ETHERTYPE_IPV4 => 4,
            ETHERTYPE_IPV6 => 6,
            _ => 0,
        },
    ))
}

fn collect_ipv4_destinations(bytes: &[u8], offset: usize) -> Result<Vec<IpAddr>, String> {
    let version_ihl = byte_at(bytes, offset, "IPv4 version and IHL")?;
    if version_ihl >> 4 != 4 {
        return Err(format!(
            "declared IPv4 frame contains IP version {}",
            version_ihl >> 4
        ));
    }
    let header_length = usize::from(version_ihl & 0x0f)
        .checked_mul(4)
        .ok_or_else(|| "IPv4 header length overflowed".to_owned())?;
    if !(20..=60).contains(&header_length) {
        return Err(format!("IPv4 IHL declares invalid length {header_length}"));
    }
    let total_length = usize::from(
        read_u16(
            bytes,
            offset
                .checked_add(2)
                .ok_or_else(|| "IPv4 total-length offset overflowed".to_owned())?,
        )
        .ok_or_else(|| "IPv4 header is truncated".to_owned())?,
    );
    if total_length < header_length {
        return Err(format!(
            "IPv4 total length {total_length} is shorter than header length {header_length}"
        ));
    }
    checked_slice(bytes, offset, total_length, "IPv4 packet")?;
    let destination = ipv4_at(
        bytes,
        offset
            .checked_add(16)
            .ok_or_else(|| "IPv4 destination offset overflowed".to_owned())?,
        "IPv4 destination",
    )?;
    let options_offset = offset
        .checked_add(20)
        .ok_or_else(|| "IPv4 options offset overflowed".to_owned())?;
    let options = checked_slice(bytes, options_offset, header_length - 20, "IPv4 options")?;
    let mut destinations = vec![IpAddr::V4(destination)];
    destinations.extend(
        ipv4_source_route_destinations(options)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(IpAddr::V4),
    );
    Ok(destinations)
}

fn collect_ipv6_destinations(bytes: &[u8], offset: usize) -> Result<Vec<IpAddr>, String> {
    let version = byte_at(bytes, offset, "IPv6 version")? >> 4;
    if version != 6 {
        return Err(format!("declared IPv6 frame contains IP version {version}"));
    }
    let header = checked_slice(bytes, offset, 40, "IPv6 header")?;
    let payload_length = usize::from(
        read_u16(
            bytes,
            offset
                .checked_add(4)
                .ok_or_else(|| "IPv6 payload-length offset overflowed".to_owned())?,
        )
        .ok_or_else(|| "IPv6 payload length is truncated".to_owned())?,
    );
    let packet_length = 40usize
        .checked_add(payload_length)
        .ok_or_else(|| "IPv6 packet length overflowed".to_owned())?;
    let packet = checked_slice(bytes, offset, packet_length, "IPv6 packet")?;
    if payload_length == 0
        && bytes
            .get(
                offset
                    .checked_add(40)
                    .ok_or_else(|| "IPv6 payload offset overflowed".to_owned())?..,
            )
            .is_some_and(|trailing| trailing.iter().any(|byte| *byte != 0))
    {
        return Err("IPv6 zero-length payload has ambiguous trailing bytes".to_owned());
    }

    let destination = ipv6_from_slice(
        header
            .get(24..40)
            .ok_or_else(|| "IPv6 destination is truncated".to_owned())?,
        "IPv6 destination",
    )?;
    let mut destinations = vec![IpAddr::V6(destination)];
    let mut next_header = byte_at(header, 6, "IPv6 next header")?;
    let mut cursor = 40usize;
    let mut remaining = DEFAULT_MAX_LAYERS;
    let mut saw_routing_header = false;

    while is_ipv6_extension(next_header) {
        if remaining == 0 {
            return Err("IPv6 extension chain exceeds the layer limit".to_owned());
        }
        remaining -= 1;
        match next_header {
            0 | 43 | 60 => {
                let fixed = checked_slice(packet, cursor, 8, "IPv6 extension header")?;
                let extension_length =
                    usize::from(byte_at(fixed, 1, "IPv6 extension header length")?)
                        .checked_add(1)
                        .and_then(|length| length.checked_mul(8))
                        .ok_or_else(|| "IPv6 extension length overflowed".to_owned())?;
                let extension =
                    checked_slice(packet, cursor, extension_length, "IPv6 extension header")?;
                if next_header == 43 {
                    if saw_routing_header {
                        return Err("multiple IPv6 routing headers are ambiguous".to_owned());
                    }
                    saw_routing_header = true;
                    collect_segment_route(destination, extension, &mut destinations)?;
                }
                next_header = byte_at(extension, 0, "IPv6 extension next header")?;
                cursor = cursor
                    .checked_add(extension_length)
                    .ok_or_else(|| "IPv6 extension offset overflowed".to_owned())?;
            }
            44 => {
                let fragment = checked_slice(packet, cursor, 8, "IPv6 fragment header")?;
                next_header = byte_at(fragment, 0, "IPv6 fragment next header")?;
                let offset_and_flags = read_u16(fragment, 2)
                    .ok_or_else(|| "IPv6 fragment offset is truncated".to_owned())?;
                cursor = cursor
                    .checked_add(8)
                    .ok_or_else(|| "IPv6 fragment offset overflowed".to_owned())?;
                if offset_and_flags & 0xfff8 != 0 {
                    if is_ipv6_extension(next_header) {
                        return Err("non-initial IPv6 fragment hides an extension chain".to_owned());
                    }
                    break;
                }
            }
            51 => {
                let fixed = checked_slice(packet, cursor, 2, "IPv6 AH header")?;
                let authentication_length =
                    usize::from(byte_at(fixed, 1, "IPv6 AH payload length")?)
                        .checked_add(2)
                        .and_then(|length| length.checked_mul(4))
                        .ok_or_else(|| "IPv6 AH length overflowed".to_owned())?;
                let authentication =
                    checked_slice(packet, cursor, authentication_length, "IPv6 AH header")?;
                next_header = byte_at(authentication, 0, "IPv6 AH next header")?;
                cursor = cursor
                    .checked_add(authentication_length)
                    .ok_or_else(|| "IPv6 AH offset overflowed".to_owned())?;
            }
            _ => break,
        }
    }
    Ok(destinations)
}

fn collect_segment_route(
    header_destination: Ipv6Addr,
    extension: &[u8],
    output: &mut Vec<IpAddr>,
) -> Result<(), String> {
    let routing_type = byte_at(extension, 2, "IPv6 routing type")?;
    if routing_type != 4 {
        return Err(format!(
            "unsupported IPv6 routing header type {routing_type}"
        ));
    }
    let segments_left = byte_at(extension, 3, "SRH segments left")?;
    let last_entry = byte_at(extension, 4, "SRH last entry")?;
    let flags = byte_at(extension, 5, "SRH flags")?;
    let segment_count = usize::from(last_entry)
        .checked_add(1)
        .ok_or_else(|| "SRH segment count overflowed".to_owned())?;
    let expected_length = segment_count
        .checked_mul(16)
        .and_then(|length| length.checked_add(8))
        .ok_or_else(|| "SRH length overflowed".to_owned())?;
    if extension.len() < expected_length {
        return Err(format!(
            "SRH length {} is shorter than segment count {segment_count}",
            extension.len()
        ));
    }
    let segment_bytes = extension
        .get(8..expected_length)
        .ok_or_else(|| "SRH segment list is truncated".to_owned())?;
    let mut segments = segment_bytes
        .chunks_exact(16)
        .map(|segment| ipv6_from_slice(segment, "SRH segment"))
        .collect::<Result<Vec<_>, _>>()?;
    segments.reverse();
    let route = validate_segment_route(
        header_destination,
        segments,
        segments_left,
        last_entry,
        flags,
    )
    .map_err(|error| error.to_string())?;
    output.extend(route.segments.into_iter().map(IpAddr::V6));
    Ok(())
}

fn is_ipv6_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60)
}

fn byte_at(bytes: &[u8], offset: usize, field: &str) -> Result<u8, String> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| format!("{field} is truncated"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let array = <[u8; 2]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u16::from_be_bytes(array))
}

fn checked_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    field: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("{field} range overflowed"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| format!("{field} is truncated"))
}

fn ipv4_at(bytes: &[u8], offset: usize, field: &str) -> Result<Ipv4Addr, String> {
    let octets = <[u8; 4]>::try_from(checked_slice(bytes, offset, 4, field)?)
        .map_err(|_| format!("{field} is truncated"))?;
    Ok(Ipv4Addr::from(octets))
}

fn ipv6_from_slice(bytes: &[u8], field: &str) -> Result<Ipv6Addr, String> {
    let octets = <[u8; 16]>::try_from(bytes).map_err(|_| format!("{field} is truncated"))?;
    Ok(Ipv6Addr::from(octets))
}
