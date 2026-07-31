// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod echo;
mod quoted_icmp;
mod reverse_flow;
mod sctp;

#[cfg(test)]
mod tests;

use packetcraftr_packet::{
    Packet,
    codec::NetworkEnvelope,
    layer::Layer,
    semantics::{self, BuiltinProtocol},
};

pub(crate) use echo::EchoMatcher;
#[doc(hidden)]
pub use quoted_icmp::{QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind};
pub(crate) use reverse_flow::ReverseFlowMatcher;

struct ReversedProtocolLayers<'request, 'response> {
    request_index: usize,
    request: &'request dyn Layer,
    response_index: usize,
    response: &'response dyn Layer,
}

#[inline(always)]
fn reversed_protocol_layers<'request, 'response>(
    protocol: BuiltinProtocol,
    request: &'request Packet,
    response: &'response Packet,
) -> Option<ReversedProtocolLayers<'request, 'response>> {
    let (request_index, request_layer) = request
        .iter()
        .enumerate()
        .find(|(_, layer)| BuiltinProtocol::of(*layer) == Some(protocol))?;
    let (response_index, response_layer) = response
        .iter()
        .enumerate()
        .find(|(_, layer)| BuiltinProtocol::of(*layer) == Some(protocol))?;
    let request_endpoints = network_endpoints_before(request, request_index)?;
    let response_endpoints = network_endpoints_before(response, response_index)?;
    if request_endpoints.source != response_endpoints.destination
        || request_endpoints.destination != response_endpoints.source
    {
        return None;
    }
    let request_outer = outer_network_endpoints(request)?;
    let response_outer = outer_network_endpoints(response)?;
    if request_outer.source != response_outer.destination
        || request_outer.destination != response_outer.source
    {
        return None;
    }
    Some(ReversedProtocolLayers {
        request_index,
        request: request_layer,
        response_index,
        response: response_layer,
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
