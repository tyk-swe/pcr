// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    Packet,
    field::FieldValue,
    matcher::{Match, ResponseMatcher},
    protocol::BuiltinProtocol,
};

use super::{
    QuotedProbeTransport, quoted_icmp_error_kind, response_source, reversed_protocol_layers,
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
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match> {
        if quoted_icmp_error_kind(request, response, QuotedProbeTransport::Icmp).is_some() {
            return Some(Match::new(150));
        }
        let layers = reversed_protocol_layers(self.protocol, request, response)?;
        for layers in &layers {
            let request_layer = layers.request;
            let response_layer = layers.response;
            if request_layer.field("type").and_then(|value| value.as_u64())
                != Some(self.request_type)
                || response_layer
                    .field("type")
                    .and_then(|value| value.as_u64())
                    != Some(self.reply_type)
            {
                return None;
            }
            if request_layer.field("code").and_then(|value| value.as_u64()) != Some(0)
                || response_layer
                    .field("code")
                    .and_then(|value| value.as_u64())
                    != Some(0)
            {
                return None;
            }
            let Some(FieldValue::Bytes(request_body)) = request_layer.field("body") else {
                return None;
            };
            let Some(FieldValue::Bytes(response_body)) = response_layer.field("body") else {
                return None;
            };
            let request_identity = request_body.first_chunk::<4>()?;
            if Some(request_identity) != response_body.first_chunk::<4>() {
                return None;
            }
        }
        Some(Match::new(100))
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<std::net::IpAddr> {
        response_source(response, self.protocol)
    }
}
