// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};

use super::error::{Constraint, Error};
use super::ipv4_option::parse_ipv4_source_routes;
use super::segment_routing::{SegmentRoute, validate_segment_route};
use bytes::Bytes;

use crate::field::WireValue;
use crate::layer::{Id, Layer};
use crate::packet::Packet;
use crate::protocol::BuiltinProtocol;
use crate::protocol::identity::{self, NetworkHeader, SegmentRouting};

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

pub fn outer_layers(packet: &Packet) -> impl Iterator<Item = &dyn Layer> {
    packet.iter().take(outer_scope_len(packet))
}

pub fn outer_ip_path(packet: &Packet) -> Result<Option<IpPath>, Error> {
    let scope = outer_scope_len(packet);
    let Some((index, header)) = packet
        .iter()
        .take(scope)
        .enumerate()
        .find_map(|(index, layer)| Some((index, identity::network_header(layer)?)))
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, scope, &header).map(Some)
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
        .find_map(|(index, layer)| Some((index, identity::network_header(layer)?)))
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, upper_layer_index, &header).map(Some)
}

pub(super) fn ip_path_at(
    packet: &Packet,
    network_index: usize,
    upper_bound: usize,
    header: &NetworkHeader,
) -> Result<IpPath, Error> {
    match header {
        NetworkHeader::V4 {
            source,
            destination,
            fragment_offset,
            more_fragments,
            options,
            ..
        } => ipv4_path(
            *source,
            *destination,
            *fragment_offset,
            *more_fragments,
            options,
        ),
        NetworkHeader::V6 {
            source,
            destination,
            ..
        } => ipv6_path(packet, network_index, upper_bound, *source, *destination),
    }
}

fn ipv4_path(
    source: std::net::Ipv4Addr,
    header_destination: std::net::Ipv4Addr,
    fragment_offset: u16,
    more_fragments: bool,
    options: &Bytes,
) -> Result<IpPath, Error> {
    reject_non_atomic_fragment(BuiltinProtocol::Ipv4.id(), fragment_offset, more_fragments)?;
    let source_route = parse_ipv4_source_routes(options)?;
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
        source: IpAddr::V4(source),
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
    source: Ipv6Addr,
    header_destination_v6: Ipv6Addr,
) -> Result<IpPath, Error> {
    let source = IpAddr::V6(source);
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
        if let Some(fragment) = identity::fragment_header(candidate) {
            reject_non_atomic_fragment(
                *candidate.protocol_id(),
                fragment.fragment_offset,
                fragment.more_fragments,
            )?;
        }
        if let Some(srh) = identity::segment_routing(candidate) {
            if segment_route.is_some() {
                return Err(Error::DuplicateSegmentRoutingHeader);
            }
            segment_route = Some(typed_segment_route(
                *candidate.protocol_id(),
                &srh,
                header_destination_v6,
            )?);
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
    protocol: Id,
    fragment_offset: u16,
    more_fragments: bool,
) -> Result<(), Error> {
    if fragment_offset != 0 || more_fragments {
        return Err(Error::NonAtomicFragment { protocol });
    }
    Ok(())
}

fn typed_segment_route(
    protocol: Id,
    srh: &SegmentRouting,
    header_destination: Ipv6Addr,
) -> Result<SegmentRoute, Error> {
    let expected_last = srh
        .segments
        .len()
        .checked_sub(1)
        .ok_or_else(|| Error::field(&protocol, SEGMENTS, Constraint::NonEmptySegments))?;
    let expected_last = u8::try_from(expected_last)
        .map_err(|_| Error::field(&protocol, SEGMENTS, Constraint::AtMost256Segments))?;
    let segments_left = wire_u8(&protocol, SEGMENTS_LEFT, &srh.segments_left, expected_last)?;
    let last_entry = wire_u8(&protocol, LAST_ENTRY, &srh.last_entry, expected_last)?;
    validate_segment_route(
        header_destination,
        srh.segments.clone(),
        segments_left,
        last_entry,
        srh.flags,
    )
}

fn wire_u8(
    protocol: &Id,
    field: &'static str,
    value: &WireValue<u8>,
    automatic: u8,
) -> Result<u8, Error> {
    match value {
        WireValue::Auto => Ok(automatic),
        WireValue::Exact(value) => Ok(*value),
        WireValue::Raw(value) if value.len() == 1 => Ok(value[0]),
        WireValue::Raw(_) => Err(Error::field(protocol, field, Constraint::OneByte)),
    }
}
