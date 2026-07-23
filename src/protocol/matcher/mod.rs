// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod echo;
mod quoted_icmp;
mod reverse_flow;
mod sctp;

#[cfg(test)]
mod tests;

use crate::packet::{
    Packet,
    codec::NetworkEnvelope,
    layer::Layer,
    semantics::{self, BuiltinProtocol},
};

pub(crate) use echo::EchoMatcher;
pub(crate) use quoted_icmp::{QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind};
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
    Some(ReversedProtocolLayers {
        request_index,
        request: request_layer,
        response_index,
        response: response_layer,
    })
}

fn network_endpoints_before(packet: &Packet, upper_layer_index: usize) -> Option<NetworkEnvelope> {
    let path = semantics::enclosing_ip_path(packet, upper_layer_index).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.final_destination,
    })
}
