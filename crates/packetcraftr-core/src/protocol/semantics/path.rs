// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};

use super::error::Error;
use super::ipv4_option::parse_ipv4_source_routes;
use super::segment_routing::{SegmentRoute, validate_segment_route};
use crate::field::WireValue;
use crate::layer::Layer;
use crate::packet::Packet;
use crate::protocol::BuiltinProtocol;
use crate::protocol::network::{Fragment, Ipv4, Ipv6, SegmentRoutingHeader};

// Field names that route errors report.
const SEGMENTS: &str = "segments";
const SEGMENTS_LEFT: &str = "segments_left";
const LAST_ENTRY: &str = "last_entry";

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

/// A built-in IP header, recognized by its layer type.
#[derive(Clone, Copy, Debug)]
pub(super) enum IpHeader<'a> {
    V4(&'a Ipv4),
    V6(&'a Ipv6),
}

impl<'a> IpHeader<'a> {
    pub(super) fn of(layer: &'a dyn Layer) -> Option<Self> {
        layer
            .downcast_ref::<Ipv4>()
            .map(Self::V4)
            .or_else(|| layer.downcast_ref::<Ipv6>().map(Self::V6))
    }
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
    let Some((index, header)) = packet
        .iter()
        .take(scope)
        .enumerate()
        .find_map(|(index, layer)| Some((index, IpHeader::of(layer)?)))
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, scope, header).map(Some)
}

/// Returns the nearest enclosing IP path. A malformed nearest header is an
/// error and can never fall through to an earlier tunnel envelope.
pub fn enclosing_ip_path(
    packet: &Packet,
    upper_layer_index: usize,
) -> Result<Option<IpPath>, Error> {
    let Some((index, header)) = packet
        .iter()
        .enumerate()
        .take(upper_layer_index)
        .rev()
        .find_map(|(index, layer)| Some((index, IpHeader::of(layer)?)))
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, upper_layer_index, header).map(Some)
}

/// Interprets the IP header at `network_index`, reading its IPv6 extension
/// chain up to `upper_bound`.
pub(super) fn ip_path_at(
    packet: &Packet,
    network_index: usize,
    upper_bound: usize,
    header: IpHeader<'_>,
) -> Result<IpPath, Error> {
    match header {
        IpHeader::V4(layer) => ipv4_path(layer),
        IpHeader::V6(layer) => ipv6_path(packet, network_index, upper_bound, layer),
    }
}

fn ipv4_path(layer: &Ipv4) -> Result<IpPath, Error> {
    let header_destination = layer.destination;
    reject_non_atomic_fragment(layer, layer.fragment_offset, layer.more_fragments)?;
    let source_route = parse_ipv4_source_routes(&layer.options)?;
    let final_destination = IpAddr::V4(source_route.final_destination(header_destination));
    let declared_route_destinations = source_route
        .declared
        .into_iter()
        .map(IpAddr::V4)
        .collect::<Vec<_>>();
    let header_destination = IpAddr::V4(header_destination);
    let mut visited_destinations = vec![header_destination];
    visited_destinations.extend(source_route.remaining.into_iter().map(IpAddr::V4));
    Ok(IpPath {
        source: IpAddr::V4(layer.source),
        header_destination,
        active_destination: header_destination,
        final_destination,
        visited_destinations,
        declared_route_destinations,
    })
}

fn ipv6_path(
    packet: &Packet,
    network_index: usize,
    upper_bound: usize,
    layer: &Ipv6,
) -> Result<IpPath, Error> {
    let source = IpAddr::V6(layer.source);
    let header_destination_v6 = layer.destination;
    let header_destination = IpAddr::V6(header_destination_v6);
    let mut segment_route = None;
    let extension_headers = packet
        .iter()
        .enumerate()
        .take(upper_bound)
        .skip(network_index.saturating_add(1))
        .map(|(_, candidate)| candidate);
    for candidate in extension_headers {
        if !BuiltinProtocol::of(candidate).is_some_and(BuiltinProtocol::is_ipv6_extension) {
            break;
        }
        if let Some(fragment) = candidate.downcast_ref::<Fragment>() {
            reject_non_atomic_fragment(
                fragment,
                fragment.fragment_offset,
                fragment.more_fragments,
            )?;
        }
        if let Some(srh) = candidate.downcast_ref::<SegmentRoutingHeader>() {
            if segment_route.is_some() {
                return Err(Error::DuplicateSegmentRoutingHeader);
            }
            segment_route = Some(typed_segment_route(srh, header_destination_v6)?);
        }
    }

    let Some(route) = segment_route else {
        return Ok(IpPath {
            source,
            header_destination,
            active_destination: header_destination,
            final_destination: header_destination,
            visited_destinations: vec![header_destination],
            declared_route_destinations: Vec::new(),
        });
    };
    let declared_route_destinations = route
        .segments
        .iter()
        .copied()
        .map(IpAddr::V6)
        .collect::<Vec<_>>();
    let mut visited_destinations: Vec<_> = route
        .segments
        .get(route.active_index.unwrap_or(0)..)
        .unwrap_or_default()
        .iter()
        .copied()
        .map(IpAddr::V6)
        .collect();
    if route.active_index.is_none() {
        visited_destinations.insert(0, IpAddr::V6(route.active_destination));
    }
    Ok(IpPath {
        source,
        header_destination,
        active_destination: IpAddr::V6(route.active_destination),
        final_destination: IpAddr::V6(route.final_destination),
        visited_destinations,
        declared_route_destinations,
    })
}

fn reject_non_atomic_fragment(
    layer: &dyn Layer,
    fragment_offset: u16,
    more_fragments: bool,
) -> Result<(), Error> {
    if fragment_offset != 0 || more_fragments {
        return Err(Error::NonAtomicFragment {
            protocol: *layer.protocol_id(),
        });
    }
    Ok(())
}

fn typed_segment_route(
    layer: &SegmentRoutingHeader,
    header_destination: Ipv6Addr,
) -> Result<SegmentRoute, Error> {
    let protocol = layer.protocol_id();
    let expected_last = layer
        .segments
        .len()
        .checked_sub(1)
        .ok_or_else(|| Error::field(protocol, SEGMENTS, "must contain at least one address"))?;
    let expected_last = u8::try_from(expected_last)
        .map_err(|_| Error::field(protocol, SEGMENTS, "contains more than 256 addresses"))?;
    let segments_left = wire_u8(layer, SEGMENTS_LEFT, &layer.segments_left, expected_last)?;
    let last_entry = wire_u8(layer, LAST_ENTRY, &layer.last_entry, expected_last)?;
    validate_segment_route(
        header_destination,
        layer.segments.clone(),
        segments_left,
        last_entry,
        layer.flags,
    )
}

/// Resolves a derived one-byte field: `Auto` takes `automatic`, and raw
/// bytes must be exactly one byte.
fn wire_u8(
    layer: &dyn Layer,
    field: &'static str,
    value: &WireValue<u8>,
    automatic: u8,
) -> Result<u8, Error> {
    match value {
        WireValue::Auto => Ok(automatic),
        WireValue::Exact(value) => Ok(*value),
        WireValue::Raw(value) if value.len() == 1 => Ok(value[0]),
        WireValue::Raw(_) => Err(Error::field(
            layer.protocol_id(),
            field,
            "is not Auto, an unsigned u8, or one raw byte",
        )),
    }
}
