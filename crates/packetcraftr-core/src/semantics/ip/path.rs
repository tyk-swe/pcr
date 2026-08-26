// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};

use super::super::{BuiltinProtocol, FieldValue, Layer, Packet};
use super::error::Error;
use super::ipv4_option::{ParsedIpv4SourceRoutes, parse_ipv4_source_routes};
use super::segment_routing::{SegmentRoute, validate_segment_route};

pub const SOURCE: &str = "source";
pub const DESTINATION: &str = "destination";
pub const SOURCE_PORT: &str = "source_port";
pub const DESTINATION_PORT: &str = "destination_port";
pub const SEGMENTS: &str = "segments";
pub const SEGMENTS_LEFT: &str = "segments_left";
pub const LAST_ENTRY: &str = "last_entry";
pub const TARGET_PROTOCOL: &str = "target_protocol";
pub const IPV4_OPTIONS: &str = "options";
pub(super) const FRAGMENT_OFFSET: &str = "fragment_offset";
pub(super) const MORE_FRAGMENTS: &str = "more_fragments";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpPath {
    pub source: IpAddr,
    pub header_destination: IpAddr,
    pub active_destination: IpAddr,
    pub final_destination: IpAddr,
    /// Route destinations still visited on the live path, including the active hop.
    pub visited_destinations: Vec<IpAddr>,
    /// Every route-bearing address declared by source routing or an SRH.
    pub declared_route_destinations: Vec<IpAddr>,
}

/// Number of directly transmitted layers through the first encapsulation boundary.
pub fn outer_scope_len(packet: &Packet) -> usize {
    packet
        .iter()
        .position(|layer| {
            BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_encapsulation_boundary)
        })
        .map_or(packet.len(), |boundary| boundary.saturating_add(1))
}

/// Layers of the directly transmitted packet, through its encapsulation boundary.
pub fn outer_layers(packet: &Packet) -> impl Iterator<Item = &dyn Layer> {
    packet.iter().take(outer_scope_len(packet))
}

pub fn outer_ip_path(packet: &Packet) -> Result<Option<IpPath>, Error> {
    let scope = outer_scope_len(packet);
    let Some((index, protocol)) =
        packet
            .iter()
            .take(scope)
            .enumerate()
            .find_map(|(index, layer)| {
                let protocol = BuiltinProtocol::of(layer)?;
                protocol.is_ip().then_some((index, protocol))
            })
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, scope, protocol).map(Some)
}

/// Returns the nearest enclosing IP path. A malformed nearest header is an
/// error and can never fall through to an earlier tunnel envelope.
pub fn enclosing_ip_path(
    packet: &Packet,
    upper_layer_index: usize,
) -> Result<Option<IpPath>, Error> {
    let Some((index, protocol)) = packet
        .iter()
        .enumerate()
        .take(upper_layer_index)
        .rev()
        .find_map(|(index, layer)| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some((index, protocol))
        })
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, upper_layer_index, protocol).map(Some)
}

pub(super) fn ip_path_at(
    packet: &Packet,
    network_index: usize,
    upper_bound: usize,
    protocol: BuiltinProtocol,
) -> Result<IpPath, Error> {
    let layer = packet
        .layer(network_index)
        .ok_or_else(|| Error::new("IP layer index is outside the packet"))?;
    let source = ip_field(layer, SOURCE, protocol)?;
    let header_destination = ip_field(layer, DESTINATION, protocol)?;

    if protocol == BuiltinProtocol::Ipv4 {
        reject_non_atomic_fragment(layer)?;
        let source_route = match layer.field(IPV4_OPTIONS) {
            Some(FieldValue::Bytes(options)) => parse_ipv4_source_routes(&options)?,
            None => ParsedIpv4SourceRoutes::default(),
            Some(_) => {
                return Err(Error::field(
                    layer.protocol_id(),
                    IPV4_OPTIONS,
                    "is not bytes",
                ));
            }
        };
        let IpAddr::V4(header_destination_v4) = header_destination else {
            unreachable!("IPv4 field extraction returned a different family");
        };
        let final_destination = IpAddr::V4(source_route.final_destination(header_destination_v4));
        let declared_route_destinations = source_route
            .declared
            .into_iter()
            .map(IpAddr::V4)
            .collect::<Vec<_>>();
        let mut visited_destinations = vec![header_destination];
        visited_destinations.extend(source_route.remaining.into_iter().map(IpAddr::V4));
        return Ok(IpPath {
            source,
            header_destination,
            active_destination: header_destination,
            final_destination,
            visited_destinations,
            declared_route_destinations,
        });
    }

    let IpAddr::V6(header_destination_v6) = header_destination else {
        unreachable!("IPv6 field extraction returned a different family");
    };
    let mut segment_route = None;
    for candidate_index in network_index.saturating_add(1)..upper_bound.min(packet.len()) {
        let candidate = packet
            .layer(candidate_index)
            .expect("bounded packet layer index");
        let Some(candidate_protocol) = BuiltinProtocol::of(candidate) else {
            break;
        };
        if !candidate_protocol.is_ipv6_extension() {
            break;
        }
        if candidate_protocol == BuiltinProtocol::Ipv6Fragment {
            reject_non_atomic_fragment(candidate)?;
        }
        if candidate_protocol == BuiltinProtocol::Ipv6Srh {
            if segment_route.is_some() {
                return Err(Error::new(
                    "an IPv6 extension chain contains more than one SRH",
                ));
            }
            segment_route = Some(typed_segment_route(candidate, header_destination_v6)?);
        }
    }

    if let Some(route) = segment_route {
        let declared_route_destinations = route
            .segments
            .iter()
            .copied()
            .map(IpAddr::V6)
            .collect::<Vec<_>>();
        #[expect(
            clippy::indexing_slicing,
            reason = "validate_segment_route keeps active_index at or below segments.len() - 1"
        )]
        let visited_destinations = route.segments[route.active_index..]
            .iter()
            .copied()
            .map(IpAddr::V6)
            .collect();
        Ok(IpPath {
            source,
            header_destination,
            active_destination: IpAddr::V6(route.active_destination),
            final_destination: IpAddr::V6(route.final_destination),
            visited_destinations,
            declared_route_destinations,
        })
    } else {
        Ok(IpPath {
            source,
            header_destination,
            active_destination: header_destination,
            final_destination: header_destination,
            visited_destinations: vec![header_destination],
            declared_route_destinations: Vec::new(),
        })
    }
}

pub(super) fn reject_non_atomic_fragment(layer: &dyn Layer) -> Result<(), Error> {
    let offset = match layer.field(FRAGMENT_OFFSET) {
        Some(FieldValue::Unsigned(value)) => value,
        None => 0,
        Some(_) => {
            return Err(Error::field(
                layer.protocol_id(),
                FRAGMENT_OFFSET,
                "is not unsigned",
            ));
        }
    };
    let more = match layer.field(MORE_FRAGMENTS) {
        Some(FieldValue::Bool(value)) => value,
        None => false,
        Some(_) => {
            return Err(Error::field(
                layer.protocol_id(),
                MORE_FRAGMENTS,
                "is not boolean",
            ));
        }
    };
    if offset != 0 || more {
        return Err(Error::new(format!(
            "non-atomic {} fragment may hide a live destination",
            layer.protocol_id()
        )));
    }
    Ok(())
}

fn typed_segment_route(
    layer: &dyn Layer,
    header_destination: Ipv6Addr,
) -> Result<SegmentRoute, Error> {
    let protocol = layer.protocol_id();
    let segments = match layer.field(SEGMENTS) {
        Some(FieldValue::List(values)) => values
            .into_iter()
            .map(|value| match value {
                FieldValue::Ipv6(value) => Ok(value),
                _ => Err(Error::field(
                    protocol,
                    SEGMENTS,
                    "contains a non-IPv6 value",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(Error::field(protocol, SEGMENTS, "is not a list"));
        }
        None => return Err(Error::field(protocol, SEGMENTS, "is missing")),
    };
    let expected_last = segments
        .len()
        .checked_sub(1)
        .ok_or_else(|| Error::field(protocol, SEGMENTS, "must contain at least one address"))?;
    let expected_last = u8::try_from(expected_last)
        .map_err(|_| Error::field(protocol, SEGMENTS, "contains more than 256 addresses"))?;
    let segments_left = wire_u8_field(layer, SEGMENTS_LEFT, expected_last)?;
    let last_entry = wire_u8_field(layer, LAST_ENTRY, expected_last)?;
    let flags = required_u8_field(layer, "flags")?;
    validate_segment_route(
        header_destination,
        segments,
        segments_left,
        last_entry,
        flags,
    )
}

fn wire_u8_field(layer: &dyn Layer, field: &str, automatic: u8) -> Result<u8, Error> {
    match layer.field(field) {
        Some(FieldValue::Unsigned(value)) => u8::try_from(value)
            .map_err(|_| Error::field(layer.protocol_id(), field, "is outside the u8 range")),
        #[expect(
            clippy::indexing_slicing,
            reason = "the arm guard checks value.len() == 1"
        )]
        Some(FieldValue::Bytes(value)) if value.len() == 1 => Ok(value[0]),
        Some(FieldValue::Text(value)) if value.eq_ignore_ascii_case("auto") => Ok(automatic),
        Some(_) => Err(Error::field(
            layer.protocol_id(),
            field,
            "is not Auto, an unsigned u8, or one raw byte",
        )),
        None => Err(Error::field(layer.protocol_id(), field, "is missing")),
    }
}

pub(super) fn required_u8_field(layer: &dyn Layer, field: &str) -> Result<u8, Error> {
    match layer.field(field) {
        Some(FieldValue::Unsigned(value)) => u8::try_from(value)
            .map_err(|_| Error::field(layer.protocol_id(), field, "is outside the u8 range")),
        Some(_) => Err(Error::field(layer.protocol_id(), field, "is not unsigned")),
        None => Err(Error::field(layer.protocol_id(), field, "is missing")),
    }
}

fn ip_field(layer: &dyn Layer, field: &str, protocol: BuiltinProtocol) -> Result<IpAddr, Error> {
    match (protocol, layer.field(field)) {
        (BuiltinProtocol::Ipv4, Some(FieldValue::Ipv4(value))) => Ok(IpAddr::V4(value)),
        (BuiltinProtocol::Ipv6, Some(FieldValue::Ipv6(value))) => Ok(IpAddr::V6(value)),
        (BuiltinProtocol::Ipv4, Some(_)) => {
            Err(Error::field(layer.protocol_id(), field, "is not IPv4"))
        }
        (BuiltinProtocol::Ipv6, Some(_)) => {
            Err(Error::field(layer.protocol_id(), field, "is not IPv6"))
        }
        (_, None) => Err(Error::field(layer.protocol_id(), field, "is missing")),
        _ => unreachable!("ip_field is only called for an IP protocol"),
    }
}
