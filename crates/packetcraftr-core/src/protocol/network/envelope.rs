// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::common::{invalid, network_from_addresses, rejected, zero_pad_to_four_bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    codec::{Addresses, Mode, NetworkEnvelope},
    field::WireValue,
    layer::Layer,
    packet::Packet,
    protocol::BuiltinProtocol,
    protocol::identity::{self, NetworkHeader, SegmentRouting},
    protocol::semantics::{Error as SemanticsError, ipv4_source_route_destination},
};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
}

pub(crate) fn is_outer_network_layer(packet: &Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip))
}

fn following_srh(packet: &Packet, index: usize) -> Option<SegmentRouting> {
    packet
        .iter()
        .skip(index.saturating_add(1))
        .take_while(|candidate| is_ipv6_extension_layer(*candidate))
        .find_map(identity::segment_routing)
}

pub(crate) fn srh_reduced(packet: &Packet, index: usize) -> bool {
    following_srh(packet, index).is_some_and(|routing| {
        matches!(routing.segments_left, WireValue::Exact(left) if usize::from(left) == routing.segments.len())
    })
}

pub(crate) fn srh_active_segment(packet: &Packet, index: usize) -> Option<Ipv6Addr> {
    let routing = following_srh(packet, index)?;
    let last = routing.segments.len().checked_sub(1)?;
    let segments_left = match &routing.segments_left {
        WireValue::Auto => last,
        WireValue::Exact(value) => usize::from(*value),
        WireValue::Raw(_) => return None,
    };
    last.checked_sub(segments_left)
        .and_then(|segment| routing.segments.get(segment))
        .copied()
}

pub(crate) fn resolve_envelope(
    name: &'static str,
    packet: &Packet,
    index: usize,
    addresses: &Addresses,
    mode: Mode,
) -> Result<NetworkEnvelope, crate::codec::Error> {
    for candidate in (0..index).rev() {
        let Some(layer) = packet.layer(candidate) else {
            continue;
        };
        if let Some(NetworkHeader::V4 {
            source,
            destination,
            options,
            ..
        }) = identity::network_header(layer)
        {
            let outer = is_outer_network_layer(packet, candidate);
            let (source, destination) = ipv4_endpoints(source, destination, outer, addresses);
            // The encoder walks these same padded bytes and reports what it
            // cannot read as `build.ipv4_options` in permissive mode, so the
            // header destination stands in for the source route. Options past
            // the header limit are refused in every mode, before any copy.
            let padded;
            let options = if options.len() > 40 {
                &options[..]
            } else {
                padded = zero_pad_to_four_bytes(&options);
                &padded
            };
            let pseudo_header_destination =
                match ipv4_source_route_destination(destination, options) {
                    Ok(final_destination) => final_destination,
                    Err(error)
                        if mode == Mode::Permissive
                            && !matches!(error, SemanticsError::Ipv4OptionsTooLong) =>
                    {
                        destination
                    }
                    Err(error) => return Err(rejected(BuiltinProtocol::Ipv4.as_str(), error)),
                };
            return Ok(network_from_addresses(
                source.into(),
                pseudo_header_destination.into(),
            ));
        }
        if let Some(NetworkHeader::V6 {
            source,
            destination,
            ..
        }) = identity::network_header(layer)
        {
            let outer = is_outer_network_layer(packet, candidate);
            let (source, destination) = ipv6_endpoints(source, destination, outer, addresses);
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination.
            let segment_routing_destination = (candidate.saturating_add(1)..index)
                .filter_map(|extension| packet.layer(extension))
                .take_while(|extension| is_ipv6_extension_layer(*extension))
                .filter_map(|extension| {
                    identity::segment_routing(extension)?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            return Ok(network_from_addresses(
                source.into(),
                segment_routing_destination.unwrap_or(destination).into(),
            ));
        }
    }
    match (addresses.source, addresses.destination) {
        (Some(source), Some(destination)) if source.is_ipv4() == destination.is_ipv4() => {
            Ok(NetworkEnvelope {
                source,
                destination,
            })
        }
        _ => Err(invalid(
            name,
            "the transport checksum requires matching source and destination IP addresses",
        )),
    }
}

pub(super) fn ipv4_endpoints(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    inherit: bool,
    addresses: &Addresses,
) -> (Ipv4Addr, Ipv4Addr) {
    let source = match addresses.source {
        Some(IpAddr::V4(inherited)) if inherit && source.is_unspecified() => inherited,
        _ => source,
    };
    let destination = match addresses.destination {
        Some(IpAddr::V4(inherited)) if inherit && destination.is_unspecified() => inherited,
        _ => destination,
    };
    (source, destination)
}

pub(super) fn ipv6_endpoints(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    inherit: bool,
    addresses: &Addresses,
) -> (Ipv6Addr, Ipv6Addr) {
    let source = match addresses.source {
        Some(IpAddr::V6(inherited)) if inherit && source.is_unspecified() => inherited,
        _ => source,
    };
    let destination = match addresses.destination {
        Some(IpAddr::V6(inherited)) if inherit && destination.is_unspecified() => inherited,
        _ => destination,
    };
    (source, destination)
}
