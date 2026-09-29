// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    codec::{Context, LayerEncodeContext, Mode, NetworkEnvelope},
    layer::Layer,
    packet::Packet,
    protocol::BuiltinProtocol,
    protocol::semantics::{Error as SemanticsError, ipv4_source_route_destination},
};

use crate::protocol::common::{invalid, network_from_addresses, rejected, zero_pad_to_four_bytes};

use super::{Ipv4, Ipv6};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
}

pub(crate) fn resolve_envelope(
    name: &'static str,
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, crate::codec::Error> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.downcast_ref::<Ipv4>() {
            let (source, destination) =
                ipv4_endpoints(ipv4, context.packet, index, context.build_context);
            // The encoder walks these same padded bytes and reports what it
            // cannot read as `build.ipv4_options` in permissive mode, so the
            // header destination stands in for the source route. Options past
            // the header limit are refused in every mode, before any copy.
            let padded;
            let options = if ipv4.options.len() > 40 {
                &ipv4.options[..]
            } else {
                padded = zero_pad_to_four_bytes(&ipv4.options);
                &padded
            };
            let pseudo_header_destination =
                match ipv4_source_route_destination(destination, options) {
                    Ok(final_destination) => final_destination,
                    Err(error)
                        if context.mode == Mode::Permissive
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
        if let Some(ipv6) = layer.downcast_ref::<Ipv6>() {
            let (source, destination) =
                ipv6_endpoints(ipv6, context.packet, index, context.build_context);
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination.
            let segment_routing_destination = (index.saturating_add(1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .downcast_ref::<super::SegmentRoutingHeader>()?
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
    match (
        context.build_context.source,
        context.build_context.destination,
    ) {
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
    layer: &Ipv4,
    packet: &Packet,
    index: usize,
    build_context: &Context,
) -> (Ipv4Addr, Ipv4Addr) {
    let inherit = is_outer_network_layer(packet, index);
    let source = match build_context.source {
        Some(IpAddr::V4(source)) if inherit && layer.source.is_unspecified() => source,
        _ => layer.source,
    };
    let destination = match build_context.destination {
        Some(IpAddr::V4(destination)) if inherit && layer.destination.is_unspecified() => {
            destination
        }
        _ => layer.destination,
    };
    (source, destination)
}

pub(super) fn ipv6_endpoints(
    layer: &Ipv6,
    packet: &Packet,
    index: usize,
    build_context: &Context,
) -> (Ipv6Addr, Ipv6Addr) {
    let inherit = is_outer_network_layer(packet, index);
    let source = match build_context.source {
        Some(IpAddr::V6(source)) if inherit && layer.source.is_unspecified() => source,
        _ => layer.source,
    };
    let destination = match build_context.destination {
        Some(IpAddr::V6(destination)) if inherit && layer.destination.is_unspecified() => {
            destination
        }
        _ => layer.destination,
    };
    (source, destination)
}

fn is_outer_network_layer(packet: &Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip))
}
