// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pseudo-header construction shared by the transport and ICMPv6 codecs.

use std::net::IpAddr;

use crate::{
    codec::{CodecError, LayerEncodeContext, NetworkEnvelope},
    layer::Layer,
};

use super::super::common::{invalid, network_from_addresses};

use super::{Ipv4, Ipv6};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    // AH participates in the IPv6 extension chain (RFC 8200), so the
    // pseudo-header scan for the final destination walks through it.
    matches!(
        layer.protocol_id().as_str(),
        "ah" | "ipv6_hop_by_hop" | "ipv6_destination_options" | "ipv6_fragment" | "ipv6_srh"
    )
}

pub(crate) fn encode_network(
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, CodecError> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let source = if ipv4.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V4(source) => Some(source),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.source)
            } else {
                ipv4.source
            };
            let destination = if ipv4.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V4(destination) => Some(destination),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.destination)
            } else {
                ipv4.destination
            };
            return Ok(network_from_addresses(source.into(), destination.into()));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = ((index + 1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<super::super::ipv6::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = if ipv6.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V6(source) => Some(source),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.source)
            } else {
                ipv6.source
            };
            let destination = if ipv6.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V6(destination) => Some(destination),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.destination)
            } else {
                ipv6.destination
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
            "transport",
            "transport checksum requires matching source and destination IP addresses",
        )),
    }
}

pub(super) fn is_outer_network_layer(packet: &crate::Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))
}
