// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::packet::{
    Packet,
    field::FieldValue,
    matcher::{MatchResult, ResponseMatcher},
    semantics::{self, BuiltinProtocol},
};
use crate::protocol::transport::Tcp;

use super::{
    QuotedProbeTransport, network_endpoints_before, quoted_icmp_error_kind,
    reversed_protocol_layers, sctp::sctp_initiate_tag,
};

#[derive(Clone, Debug)]
pub(crate) struct ReverseFlowMatcher {
    protocol: BuiltinProtocol,
}

impl ReverseFlowMatcher {
    pub(crate) fn new(protocol: BuiltinProtocol) -> Self {
        debug_assert!(matches!(
            protocol,
            BuiltinProtocol::Tcp | BuiltinProtocol::Udp | BuiltinProtocol::Sctp
        ));
        Self { protocol }
    }
}

impl ResponseMatcher for ReverseFlowMatcher {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult {
        let transport = match self.protocol {
            BuiltinProtocol::Tcp => QuotedProbeTransport::Tcp,
            BuiltinProtocol::Udp => QuotedProbeTransport::Udp,
            BuiltinProtocol::Sctp => QuotedProbeTransport::Sctp,
            _ => return MatchResult::no_match(),
        };
        if quoted_icmp_error_kind(request, response, transport).is_some() {
            return MatchResult::matched(
                150,
                match transport {
                    QuotedProbeTransport::Sctp => "matching quoted SCTP ICMP error response",
                    _ => "matching quoted ICMP error response",
                },
            );
        }
        let Some(layers) = reversed_protocol_layers(self.protocol, request, response) else {
            return MatchResult::no_match();
        };
        let request_layer_index = layers.request_index;
        let request_layer = layers.request;
        let response_layer_index = layers.response_index;
        let response_layer = layers.response;
        if !semantics::transport_keys_are_reversed(request_layer, response_layer) {
            return MatchResult::no_match();
        }
        match self.protocol {
            BuiltinProtocol::Tcp => {
                let Some(request_flags) = request_layer
                    .field("flags")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u16::try_from(value).ok())
                else {
                    return MatchResult::no_match();
                };
                let Some(request_sequence) = request_layer
                    .field("sequence")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                else {
                    return MatchResult::no_match();
                };
                let request_acknowledgment = request_layer
                    .field("acknowledgment")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                let Some(response_flags) = response_layer
                    .field("flags")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u16::try_from(value).ok())
                else {
                    return MatchResult::no_match();
                };
                let response_acknowledgment = response_layer
                    .field("acknowledgment")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                let response_sequence = response_layer
                    .field("sequence")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                let Some(request_payload_length) = tcp_payload_length(request, request_layer_index)
                else {
                    return MatchResult::no_match();
                };
                let expected_acknowledgment = request_sequence
                    .wrapping_add(request_payload_length)
                    .wrapping_add(u32::from(request_flags & Tcp::SYN != 0))
                    .wrapping_add(u32::from(request_flags & Tcp::FIN != 0));
                let has_ack = response_flags & Tcp::ACK != 0;
                let has_rst = response_flags & Tcp::RST != 0;
                if has_ack {
                    if response_acknowledgment != expected_acknowledgment {
                        return MatchResult::no_match();
                    }
                } else if has_rst {
                    if response_sequence != request_acknowledgment {
                        return MatchResult::no_match();
                    }
                } else {
                    return MatchResult::no_match();
                }
                if has_rst && response_flags & Tcp::SYN != 0 {
                    return MatchResult::no_match();
                }
                MatchResult::matched(200, "reverse TCP tuple and sequence state")
            }
            BuiltinProtocol::Sctp => {
                if request_layer
                    .field("verification_tag")
                    .and_then(|value| value.as_u64())
                    != Some(0)
                {
                    return MatchResult::no_match();
                }
                let Some((request_initiate_tag, _)) =
                    sctp_initiate_tag(request, request_layer_index, 1)
                else {
                    return MatchResult::no_match();
                };
                if request_initiate_tag == 0
                    || sctp_initiate_tag(response, response_layer_index, 2).is_none()
                    || response_layer
                        .field("verification_tag")
                        .and_then(|value| value.as_u64())
                        != Some(u64::from(request_initiate_tag))
                {
                    return MatchResult::no_match();
                }
                MatchResult::matched(200, "reverse SCTP tuple and INIT verification tag")
            }
            _ => MatchResult::matched(100, format!("reverse {} tuple", self.protocol.as_str())),
        }
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<IpAddr> {
        let response_layer_index = response
            .iter()
            .position(|layer| BuiltinProtocol::of(layer) == Some(self.protocol))?;
        network_endpoints_before(response, response_layer_index).map(|endpoints| endpoints.source)
    }
}

fn tcp_payload_length(packet: &Packet, tcp_layer_index: usize) -> Option<u32> {
    if let Some(encoded_length) = packet.encoded_payload_length(tcp_layer_index) {
        let trailing_padding = packet
            .iter()
            .skip(tcp_layer_index + 1)
            .rev()
            .take_while(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Padding))
            .filter(|layer| {
                layer
                    .field("outside_layer")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| usize::try_from(value).ok())
                    .is_none_or(|outside_layer| tcp_layer_index >= outside_layer)
            })
            .try_fold(0_usize, |total, layer| {
                let FieldValue::Bytes(bytes) = layer.field("bytes")? else {
                    return None;
                };
                total.checked_add(bytes.len())
            })?;
        return u32::try_from(encoded_length.checked_sub(trailing_padding)?).ok();
    }

    let mut payload_length = 0_u32;
    for layer in packet.iter().skip(tcp_layer_index + 1) {
        match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Padding) => break,
            Some(BuiltinProtocol::Raw) => {
                let FieldValue::Bytes(bytes) = layer.field("bytes")? else {
                    return None;
                };
                payload_length = payload_length.checked_add(u32::try_from(bytes.len()).ok()?)?;
            }
            // The built-in TCP binding decodes its opaque payload as Raw. An
            // unknown child cannot be assigned a sequence-space length from
            // reflective fields without guessing its encoded representation.
            _ => return None,
        }
    }
    Some(payload_length)
}

#[cfg(test)]
mod tests;
