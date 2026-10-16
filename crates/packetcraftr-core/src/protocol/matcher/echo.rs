// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    matcher::{Match, ResponseMatcher},
    packet::Packet,
    protocol::BuiltinProtocol,
};

use super::{
    IcmpMessage, QuotedTransport, quoted_icmp_error, response_source, reversed_protocol_layers,
};

#[derive(Clone, Debug)]
pub(crate) struct EchoMatcher {
    protocol: BuiltinProtocol,
    request_type: u8,
    reply_type: u8,
}

impl EchoMatcher {
    pub(crate) fn v4() -> Self {
        Self {
            protocol: BuiltinProtocol::Icmpv4,
            request_type: 8,
            reply_type: 0,
        }
    }

    pub(crate) fn v6() -> Self {
        Self {
            protocol: BuiltinProtocol::Icmpv6,
            request_type: 128,
            reply_type: 129,
        }
    }
}

impl ResponseMatcher for EchoMatcher {
    fn uses_builtin_response_identity(&self) -> bool {
        true
    }

    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match> {
        if quoted_icmp_error(request, response, QuotedTransport::Icmp).is_some() {
            return Some(Match::new(150));
        }
        let layers = reversed_protocol_layers(self.protocol, request, response)?;
        for layers in &layers {
            let request = IcmpMessage::of(layers.request)?;
            let response = IcmpMessage::of(layers.response)?;
            if request.code != 0 || response.code != 0 {
                return None;
            }
            let min_body_len = match (self.protocol, request.icmp_type, response.icmp_type) {
                (_, req, resp) if req == self.request_type && resp == self.reply_type => 4,
                (BuiltinProtocol::Icmpv4, 13, 14) => 16,
                (BuiltinProtocol::Icmpv4, 17, 18) => 8,
                _ => return None,
            };
            if request.body.len() < min_body_len
                || response.body.len() < min_body_len
                || request.body.get(..4)? != response.body.get(..4)?
            {
                return None;
            }
        }
        Some(Match::new(100))
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<std::net::IpAddr> {
        response_source(response, self.protocol)
    }
}
