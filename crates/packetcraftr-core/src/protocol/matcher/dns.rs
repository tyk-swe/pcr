// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS application-layer response attribution.

use crate::{
    matcher::{Match, ResponseMatcher},
    packet::Packet,
    protocol::{BuiltinProtocol, application::dns::Dns},
};

use super::{ReversedProtocolLayers, response_source, reversed_protocol_layers};

/// A structured DNS answer owns its reversed UDP conversation. Verifying the
/// application identity means a wrong identifier, opcode, direction, or
/// question can never attribute the reply through the weaker transport-tuple
/// match, so the confidence sits above stateful transport correlation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DnsMatcher;

impl ResponseMatcher for DnsMatcher {
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match> {
        let pairs = reversed_protocol_layers(BuiltinProtocol::Dns, request, response)?;
        pairs.iter().all(answers).then(|| Match::new(250))
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<std::net::IpAddr> {
        response_source(response, BuiltinProtocol::Dns)
    }
}

/// Whether `pair` is a DNS answer to the request's query: the layers sit
/// directly on UDP, the reply flips the direction bit, and the transaction
/// identifier, opcode, and complete ordered question section all echo.
fn answers(pair: &ReversedProtocolLayers<'_, '_>) -> bool {
    let (Some(query), Some(reply)) = (
        pair.request.as_any().downcast_ref::<Dns>(),
        pair.response.as_any().downcast_ref::<Dns>(),
    ) else {
        return false;
    };
    answers_query(query, reply)
}

/// The scope is unicast DNS-over-UDP: the layer must sit directly on a UDP
/// header. DNS-over-TCP replies carry a length prefix this matcher does not
/// adjudicate.
pub(super) fn udp_child(packet: &Packet, index: usize) -> bool {
    index > 0
        && packet
            .layer(index - 1)
            .is_some_and(|parent| BuiltinProtocol::Udp.identifies(parent))
}

/// `Name` equality folds ASCII letter case only and operates on decoded
/// labels, so wire spelling and compression change nothing.
fn answers_query(query: &Dns, reply: &Dns) -> bool {
    !query.response
        && reply.response
        && query.id == reply.id
        && query.opcode == reply.opcode
        && query.questions == reply.questions
}
