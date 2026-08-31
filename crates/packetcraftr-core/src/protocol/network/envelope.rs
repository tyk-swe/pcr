// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pseudo-header construction shared by the transport and ICMPv6 codecs.

use std::net::IpAddr;

use crate::{
    codec::{LayerEncodeContext, NetworkEnvelope},
    layer::Layer,
    protocol::BuiltinProtocol,
    semantics::ipv4_source_route_destination,
};

use crate::protocol::common::{invalid, network_from_addresses};

use super::{Ipv4, Ipv6};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    // AH participates in the IPv6 extension chain (RFC 8200), so the
    // pseudo-header scan for the final destination walks through it, which is
    // exactly what the catalog's extension predicate answers.
    BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
}

/// Extension headers whose wire encoding carries its own length, so a chain
/// walk can step over them: Hop-by-Hop (0), Routing (43), AH (51), and
/// Destination Options (60).
pub(crate) const fn is_walkable_ipv6_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 51 | 60)
}

/// Wire length of one walkable extension header, from the protocol number
/// that selected it and its Hdr Ext Len byte. Hop-by-Hop, Routing, and
/// Destination Options count 8-byte units excluding the first; AH counts
/// 4-byte words minus two and can never be shorter than its 12 fixed bytes.
pub(crate) fn ipv6_extension_header_length(next_header: u8, encoded_length: u8) -> Option<usize> {
    match next_header {
        0 | 43 | 60 => usize::from(encoded_length)
            .checked_add(1)
            .and_then(|units| units.checked_mul(8)),
        51 => usize::from(encoded_length)
            .checked_add(2)
            .and_then(|words| words.checked_mul(4))
            .filter(|length| *length >= 12),
        _ => None,
    }
}

/// `name` is the calling codec's protocol, so a missing or mismatched
/// envelope is reported against a protocol the catalog actually has.
pub(crate) fn resolve_envelope(
    name: &str,
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, crate::codec::Error> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let inherit_source = inherit_context && ipv4.source.is_unspecified();
            let inherit_destination = inherit_context && ipv4.destination.is_unspecified();
            let source = match context.build_context.source {
                Some(IpAddr::V4(source)) if inherit_source => source,
                _ => ipv4.source,
            };
            let destination = match context.build_context.destination {
                Some(IpAddr::V4(destination)) if inherit_destination => destination,
                _ => ipv4.destination,
            };
            let pseudo_header_destination =
                ipv4_source_route_destination(destination, &ipv4.options)
                    .map_err(|error| invalid(BuiltinProtocol::Ipv4.as_str(), error.to_string()))?;
            return Ok(network_from_addresses(
                source.into(),
                pseudo_header_destination.into(),
            ));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let inherit_source = inherit_context && ipv6.source.is_unspecified();
            let inherit_destination = inherit_context && ipv6.destination.is_unspecified();
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = (index.saturating_add(1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<crate::protocol::ipv6::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = match context.build_context.source {
                Some(IpAddr::V6(source)) if inherit_source => source,
                _ => ipv6.source,
            };
            let destination = match context.build_context.destination {
                Some(IpAddr::V6(destination)) if inherit_destination => destination,
                _ => ipv6.destination,
            };
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

pub(super) fn is_outer_network_layer(packet: &crate::Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip))
}
