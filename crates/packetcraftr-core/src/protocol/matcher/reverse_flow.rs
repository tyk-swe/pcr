// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::transport::Tcp;
use crate::{
    Packet,
    field::FieldValue,
    matcher::{Match, ResponseMatcher},
    protocol::BuiltinProtocol,
};

use super::{
    QuotedProbeTransport, ReversedProtocolLayers, quoted_icmp_error_kind, response_source,
    reversed_protocol_layers, sctp::sctp_initiate_tag, unsigned_field,
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
    fn matches(&self, request: &Packet, response: &Packet) -> Option<Match> {
        let transport = match self.protocol {
            BuiltinProtocol::Tcp => QuotedProbeTransport::Tcp,
            BuiltinProtocol::Udp => QuotedProbeTransport::Udp,
            BuiltinProtocol::Sctp => QuotedProbeTransport::Sctp,
            _ => return None,
        };
        if quoted_icmp_error_kind(request, response, transport).is_some() {
            return Some(Match::new(150));
        }
        let layers = reversed_protocol_layers(self.protocol, request, response)?;
        match self.protocol {
            BuiltinProtocol::Tcp => match_tcp(request, &layers),
            BuiltinProtocol::Sctp => match_sctp(request, response, &layers),
            // UDP has no further state to confirm: reverse tuples are the
            // whole attribution.
            _ => Some(Match::new(100)),
        }
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<std::net::IpAddr> {
        response_source(response, self.protocol)
    }
}

fn match_tcp(request: &Packet, layers: &[ReversedProtocolLayers<'_, '_>]) -> Option<Match> {
    for layers in layers {
        let request_layer = layers.request;
        let response_layer = layers.response;
        let request_flags = unsigned_field::<u16>(request_layer, "flags")?;
        let request_sequence = unsigned_field::<u32>(request_layer, "sequence")?;
        let response_flags = unsigned_field::<u16>(response_layer, "flags")?;
        let request_payload_length = tcp_payload_length(request, layers.request_index)?;
        let expected_acknowledgment = request_sequence
            .wrapping_add(request_payload_length)
            .wrapping_add(u32::from(request_flags & Tcp::SYN != 0))
            .wrapping_add(u32::from(request_flags & Tcp::FIN != 0));
        let has_ack = response_flags & Tcp::ACK != 0;
        let has_rst = response_flags & Tcp::RST != 0;
        if has_ack {
            let response_acknowledgment = unsigned_field::<u32>(response_layer, "acknowledgment")?;
            if response_acknowledgment != expected_acknowledgment {
                return None;
            }
        } else if has_rst && request_flags & Tcp::ACK != 0 {
            let request_acknowledgment = unsigned_field::<u32>(request_layer, "acknowledgment")?;
            let response_sequence = unsigned_field::<u32>(response_layer, "sequence")?;
            if response_sequence != request_acknowledgment {
                return None;
            }
        } else {
            return None;
        }
        if has_rst && response_flags & Tcp::SYN != 0 {
            return None;
        }
    }
    Some(Match::new(200))
}

fn match_sctp(
    request: &Packet,
    response: &Packet,
    layers: &[ReversedProtocolLayers<'_, '_>],
) -> Option<Match> {
    for layers in layers {
        if layers
            .request
            .field("verification_tag")
            .and_then(|value| value.as_u64())
            != Some(0)
        {
            return None;
        }
        let (request_initiate_tag, _) = sctp_initiate_tag(request, layers.request_index, 1)?;
        if request_initiate_tag == 0
            || sctp_initiate_tag(response, layers.response_index, 2).is_none()
            || layers
                .response
                .field("verification_tag")
                .and_then(|value| value.as_u64())
                != Some(u64::from(request_initiate_tag))
        {
            return None;
        }
    }
    Some(Match::new(200))
}

fn tcp_payload_length(packet: &Packet, tcp_layer_index: usize) -> Option<u32> {
    let first_child_index = tcp_layer_index.checked_add(1)?;
    if let Some(encoded_length) = packet.encoded_payload_length(tcp_layer_index) {
        let trailing_padding = packet
            .iter()
            .skip(first_child_index)
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
    for layer in packet.iter().skip(first_child_index) {
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
