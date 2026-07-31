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
    if !network_paths_are_reversed(request, request_index, response, response_index) {
        return None;
    }
    Some(ReversedProtocolLayers {
        request_index,
        request: request_layer,
        response_index,
        response: response_layer,
    })
}

fn network_paths_are_reversed(
    request: &Packet,
    request_upper_bound: usize,
    response: &Packet,
    response_upper_bound: usize,
) -> bool {
    let request_networks = network_layers_before(request, request_upper_bound);
    let response_networks = network_layers_before(response, response_upper_bound);
    if request_networks.len() != response_networks.len() {
        return false;
    }

    request_networks.iter().zip(&response_networks).all(
        |(&(request_index, request_protocol), &(response_index, response_protocol))| {
            if request_protocol != response_protocol {
                return false;
            }
            let request_path = semantics::enclosing_ip_path(
                request,
                next_network_or_upper_bound(&request_networks, request_index, request_upper_bound),
            )
            .ok()
            .flatten();
            let response_path = semantics::enclosing_ip_path(
                response,
                next_network_or_upper_bound(
                    &response_networks,
                    response_index,
                    response_upper_bound,
                ),
            )
            .ok()
            .flatten();
            request_path
                .zip(response_path)
                .is_some_and(|(request, response)| {
                    request.source == response.final_destination
                        && request.final_destination == response.source
                })
        },
    ) && encapsulation_layers_match(request, &request_networks, response, &response_networks)
}

fn network_layers_before(packet: &Packet, upper_bound: usize) -> Vec<(usize, BuiltinProtocol)> {
    packet
        .iter()
        .enumerate()
        .take(upper_bound)
        .filter_map(|(index, layer)| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some((index, protocol))
        })
        .collect()
}

fn next_network_or_upper_bound(
    networks: &[(usize, BuiltinProtocol)],
    current_index: usize,
    upper_bound: usize,
) -> usize {
    networks
        .iter()
        .find_map(|(index, _)| (*index > current_index).then_some(*index))
        .unwrap_or(upper_bound)
}

fn encapsulation_layers_match(
    request: &Packet,
    request_networks: &[(usize, BuiltinProtocol)],
    response: &Packet,
    response_networks: &[(usize, BuiltinProtocol)],
) -> bool {
    request_networks
        .windows(2)
        .zip(response_networks.windows(2))
        .all(|(request_pair, response_pair)| {
            let protocols_between = |packet: &Packet, pair: &[(usize, BuiltinProtocol)]| {
                packet
                    .iter()
                    .skip(pair[0].0 + 1)
                    .take(pair[1].0 - pair[0].0 - 1)
                    .filter_map(BuiltinProtocol::of)
                    .filter(|protocol| !protocol.is_ipv6_extension())
                    .collect::<Vec<_>>()
            };
            protocols_between(request, request_pair) == protocols_between(response, response_pair)
        })
}

fn network_endpoints_before(packet: &Packet, upper_layer_index: usize) -> Option<NetworkEnvelope> {
    let path = semantics::enclosing_ip_path(packet, upper_layer_index).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.final_destination,
    })
}
