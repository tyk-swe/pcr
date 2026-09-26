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
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match> {
        if quoted_icmp_error(request, response, QuotedTransport::Icmp).is_some() {
            return Some(Match::new(150));
        }
        let layers = reversed_protocol_layers(self.protocol, request, response)?;
        for layers in &layers {
            let request = IcmpMessage::of(layers.request)?;
            let response = IcmpMessage::of(layers.response)?;
            if request.icmp_type != self.request_type
                || response.icmp_type != self.reply_type
                || request.code != 0
                || response.code != 0
            {
                return None;
            }
            // The echo identifier and sequence (body bytes 0-4) are the
            // correlation identity; the variable rest of the echo body is not
            // compared.
            if request.body.get(..4)? != response.body.get(..4)? {
                return None;
            }
        }
        Some(Match::new(100))
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<std::net::IpAddr> {
        response_source(response, self.protocol)
    }
}
