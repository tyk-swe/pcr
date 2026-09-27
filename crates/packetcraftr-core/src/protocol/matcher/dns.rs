// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    matcher::{Match, ResponseMatcher},
    packet::Packet,
    protocol::{BuiltinProtocol, application::dns::Dns},
};

use super::{ReversedProtocolLayers, response_source, reversed_protocol_layers};

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

fn answers(pair: &ReversedProtocolLayers<'_, '_>) -> bool {
    let (Some(query), Some(reply)) = (
        pair.request.downcast_ref::<Dns>(),
        pair.response.downcast_ref::<Dns>(),
    ) else {
        return false;
    };
    answers_query(query, reply)
}

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
