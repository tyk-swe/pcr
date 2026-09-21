// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod dns;
mod echo;
mod quoted_icmp;
mod reverse_flow;
mod sctp;

use crate::{
    codec::NetworkEnvelope, layer::Layer, packet::Packet, packet::semantics,
    protocol::BuiltinProtocol,
};

pub(crate) use dns::DnsMatcher;
pub(crate) use echo::EchoMatcher;
// Exported for the workflow crate's probe classification; not part of the
// documented public API.
#[doc(hidden)]
pub use quoted_icmp::{QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind};
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
    if !outer_envelopes_reversed(request, response) {
        return None;
    }

    let mut request_layers = matchable_layers(request);
    let mut response_layers = matchable_layers(response);
    let mut deepest_protocol = None;
    let mut reversed = Vec::new();
    loop {
        let (request_layer, response_layer) = match (request_layers.next(), response_layers.next())
        {
            (Some(request), Some(response)) => (request, response),
            (None, None) => break,
            _ => return None,
        };
        deepest_protocol = Some(request_layer.1);
        reversed_layer_pair(request, request_layer, response, response_layer)?;
        if request_layer.1 == protocol {
            reversed.push(ReversedProtocolLayers {
                request_index: request_layer.0,
                request: request_layer.2,
                response_index: response_layer.0,
                response: response_layer.2,
            });
        }
    }
    (deepest_protocol == Some(protocol) && !reversed.is_empty()).then_some(reversed)
}

fn outer_envelopes_reversed(request: &Packet, response: &Packet) -> bool {
    let (Some(request_outer), Some(response_outer)) = (
        outer_network_endpoints(request),
        outer_network_endpoints(response),
    ) else {
        return false;
    };
    request_outer.source == response_outer.destination
        && request_outer.destination == response_outer.source
}

/// Whether one matchable pair at the same stack position reverses: identical
/// protocols, reversed enclosing network endpoints, and reversed transport
/// keys where the protocol carries them. The response's enclosing envelope is
/// returned so callers can attribute its responder.
fn reversed_layer_pair(
    request: &Packet,
    request_layer: (usize, BuiltinProtocol, &dyn Layer),
    response: &Packet,
    response_layer: (usize, BuiltinProtocol, &dyn Layer),
) -> Option<NetworkEnvelope> {
    let (request_index, request_protocol, request_layer) = request_layer;
    let (response_index, response_protocol, response_layer) = response_layer;
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
    Some(response_endpoints)
}

/// Whether the complete transport stack reverses, ignoring DNS application
/// identity. The deepest transport must be `transport`; enclosing tunnel
/// transports and every enclosing network envelope must also reverse.
///
/// The returned address is the source of the deepest transport's envelope.
/// Exported for workflow classification; not part of the documented public API.
#[doc(hidden)]
pub fn transport_tuple_reversed(
    request: &Packet,
    response: &Packet,
    transport: BuiltinProtocol,
) -> Option<std::net::IpAddr> {
    if !outer_envelopes_reversed(request, response) {
        return None;
    }
    let without_dns =
        |(_, protocol, _): &(usize, BuiltinProtocol, &dyn Layer)| *protocol != BuiltinProtocol::Dns;
    let mut response_layers = matchable_layers(response).filter(without_dns);
    let mut deepest = None;
    for request_layer in matchable_layers(request).filter(without_dns) {
        let response_layer = response_layers.next()?;
        let response_endpoints =
            reversed_layer_pair(request, request_layer, response, response_layer)?;
        deepest = Some((request_layer.1, response_endpoints.source));
    }
    if response_layers.next().is_some() {
        return None;
    }
    let (protocol, responder) = deepest?;
    (protocol == transport).then_some(responder)
}

fn matchable_layers(
    packet: &Packet,
) -> impl Iterator<Item = (usize, BuiltinProtocol, &dyn Layer)> + '_ {
    packet.iter().enumerate().filter_map(|(index, layer)| {
        let protocol = BuiltinProtocol::of(layer)?;
        // DNS owns only UDP exchanges. TCP retains sequence-aware ownership,
        // including responses consisting solely of an acknowledgment.
        let owns_layer = protocol != BuiltinProtocol::Dns || dns::udp_child(packet, index);
        (protocol.has_matcher() && owns_layer).then_some((index, protocol, layer))
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
