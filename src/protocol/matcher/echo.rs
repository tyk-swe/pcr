// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::packet::{
    Packet,
    field::FieldValue,
    matcher::{MatchResult, ResponseMatcher},
    semantics::BuiltinProtocol,
};

use super::{
    QuotedProbeTransport, network_endpoints_before, quoted_icmp_error_kind,
    reversed_protocol_layers,
};

#[derive(Clone, Debug)]
pub(crate) struct EchoMatcher {
    protocol: BuiltinProtocol,
    request_type: u64,
    reply_type: u64,
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
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult {
        if quoted_icmp_error_kind(request, response, QuotedProbeTransport::Icmp).is_some() {
            return MatchResult::matched(150, "matching quoted ICMP error response");
        }
        let Some(layers) = reversed_protocol_layers(self.protocol, request, response) else {
            return MatchResult::no_match();
        };
        let request_layer = layers.request;
        let response_layer = layers.response;
        if request_layer.field("type").and_then(|value| value.as_u64()) != Some(self.request_type)
            || response_layer
                .field("type")
                .and_then(|value| value.as_u64())
                != Some(self.reply_type)
        {
            return MatchResult::no_match();
        }
        if request_layer.field("code").and_then(|value| value.as_u64()) != Some(0)
            || response_layer
                .field("code")
                .and_then(|value| value.as_u64())
                != Some(0)
        {
            return MatchResult::no_match();
        }
        let Some(FieldValue::Bytes(request_body)) = request_layer.field("body") else {
            return MatchResult::no_match();
        };
        let Some(FieldValue::Bytes(response_body)) = response_layer.field("body") else {
            return MatchResult::no_match();
        };
        if request_body.len() < 4
            || response_body.len() < 4
            || request_body[..4] != response_body[..4]
        {
            return MatchResult::no_match();
        }
        MatchResult::matched(100, "matching ICMP echo identifier and sequence")
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<IpAddr> {
        let response_layer_index = response
            .iter()
            .position(|layer| BuiltinProtocol::of(layer) == Some(self.protocol))?;
        network_endpoints_before(response, response_layer_index).map(|endpoints| endpoints.source)
    }
}
