// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod echo;
mod quoted_icmp;
mod reverse_flow;
mod sctp;

use crate::{
    Packet,
    codec::NetworkEnvelope,
    layer::Layer,
    semantics::{self, BuiltinProtocol},
};

pub(crate) use echo::EchoMatcher;
#[doc(hidden)]
pub use quoted_icmp::{QuotedIcmpReason, QuotedProbeTransport, quoted_icmp_error_kind};
pub(crate) use reverse_flow::ReverseFlowMatcher;

struct ReversedProtocolLayers<'request, 'response> {
    request_index: usize,
    request: &'request dyn Layer,
    response_index: usize,
    response: &'response dyn Layer,
}

/// Pairs every occurrence of `protocol` only after the complete directly
/// matchable stack has reversed. The deepest matcher owns a direct response;
/// enclosing tunnel transports are evidence it must validate, not independent
/// reasons to accept an otherwise unrelated inner packet.
fn reversed_protocol_layers<'request, 'response>(
    protocol: BuiltinProtocol,
    request: &'request Packet,
    response: &'response Packet,
) -> Option<Vec<ReversedProtocolLayers<'request, 'response>>> {
    let request_outer = outer_network_endpoints(request)?;
    let response_outer = outer_network_endpoints(response)?;
    if request_outer.source != response_outer.destination
        || request_outer.destination != response_outer.source
    {
        return None;
    }

    let mut request_layers = matchable_layers(request);
    let mut response_layers = matchable_layers(response);
    let mut deepest_protocol = None;
    let mut reversed = Vec::new();
    loop {
        let (
            (request_index, request_protocol, request_layer),
            (response_index, response_protocol, response_layer),
        ) = match (request_layers.next(), response_layers.next()) {
            (Some(request), Some(response)) => (request, response),
            (None, None) => break,
            _ => return None,
        };
        deepest_protocol = Some(request_protocol);
        if request_protocol != response_protocol {
            return None;
        }
        let request_endpoints = network_endpoints_before(request, request_index)?;
        let response_endpoints = network_endpoints_before(response, response_index)?;
        if request_endpoints.source != response_endpoints.destination
            || request_endpoints.destination != response_endpoints.source
        {
            return None;
        }
        if matches!(
            request_protocol,
            BuiltinProtocol::Tcp | BuiltinProtocol::Udp | BuiltinProtocol::Sctp
        ) && !semantics::transport_keys_are_reversed(request_layer, response_layer)
        {
            return None;
        }
        if request_protocol == protocol {
            reversed.push(ReversedProtocolLayers {
                request_index,
                request: request_layer,
                response_index,
                response: response_layer,
            });
        }
    }
    (deepest_protocol == Some(protocol) && !reversed.is_empty()).then_some(reversed)
}

fn matchable_layers(
    packet: &Packet,
) -> impl Iterator<Item = (usize, BuiltinProtocol, &dyn Layer)> + '_ {
    packet.iter().enumerate().filter_map(|(index, layer)| {
        let protocol = BuiltinProtocol::of(layer)?;
        protocol.has_matcher().then_some((index, protocol, layer))
    })
}

/// The envelope of the packet transmitted on the wire: the outermost IP path,
/// ignoring anything behind an encapsulation boundary. A direct reply must
/// reverse it; reversing only an inner tunnel tuple is not correlation.
fn outer_network_endpoints(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = semantics::outer_ip_path(packet).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.final_destination,
    })
}

fn network_endpoints_before(packet: &Packet, upper_layer_index: usize) -> Option<NetworkEnvelope> {
    let path = semantics::enclosing_ip_path(packet, upper_layer_index).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.final_destination,
    })
}

fn unsigned_field<T>(layer: &dyn Layer, field: &str) -> Option<T>
where
    T: TryFrom<u64>,
{
    T::try_from(layer.field(field)?.as_u64()?).ok()
}

fn response_source(response: &Packet, protocol: BuiltinProtocol) -> Option<std::net::IpAddr> {
    let index = response
        .iter()
        .rposition(|layer| BuiltinProtocol::of(layer) == Some(protocol))?;
    network_endpoints_before(response, index).map(|endpoints| endpoints.source)
}
