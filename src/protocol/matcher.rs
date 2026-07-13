// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::packet::internal::{FieldValue, MatchResult, NetworkEnvelope, Packet, ResponseMatcher};

#[derive(Clone, Debug)]
pub(crate) struct ReverseFlowMatcher {
    protocol: &'static str,
}

impl ReverseFlowMatcher {
    pub(crate) fn new(protocol: &'static str) -> Self {
        Self { protocol }
    }
}

impl ResponseMatcher for ReverseFlowMatcher {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult {
        let Some((request_layer_index, request_layer)) = request
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some((response_layer_index, response_layer)) = response
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some(request_endpoints) = network_endpoints_before(request, request_layer_index) else {
            return MatchResult::no_match();
        };
        let Some(response_endpoints) = network_endpoints_before(response, response_layer_index)
        else {
            return MatchResult::no_match();
        };
        if request_endpoints.source != response_endpoints.destination
            || request_endpoints.destination != response_endpoints.source
        {
            return MatchResult::no_match();
        }
        let Some(request_source_port) = request_layer
            .field("source_port")
            .and_then(|value| value.as_u64())
        else {
            return MatchResult::no_match();
        };
        let Some(request_destination_port) = request_layer
            .field("destination_port")
            .and_then(|value| value.as_u64())
        else {
            return MatchResult::no_match();
        };
        let Some(response_source_port) = response_layer
            .field("source_port")
            .and_then(|value| value.as_u64())
        else {
            return MatchResult::no_match();
        };
        let Some(response_destination_port) = response_layer
            .field("destination_port")
            .and_then(|value| value.as_u64())
        else {
            return MatchResult::no_match();
        };
        if request_source_port == response_destination_port
            && request_destination_port == response_source_port
        {
            if self.protocol == "tcp" {
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
                    .wrapping_add(u32::from(request_flags & super::transport::Tcp::SYN != 0))
                    .wrapping_add(u32::from(request_flags & super::transport::Tcp::FIN != 0));
                let has_ack = response_flags & super::transport::Tcp::ACK != 0;
                let has_rst = response_flags & super::transport::Tcp::RST != 0;
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
                if has_rst && response_flags & super::transport::Tcp::SYN != 0 {
                    return MatchResult::no_match();
                }
                MatchResult::matched(200, "reverse TCP tuple and sequence state")
            } else {
                MatchResult::matched(100, format!("reverse {} tuple", self.protocol))
            }
        } else {
            MatchResult::no_match()
        }
    }

    fn responder(&self, _request: &Packet, response: &Packet) -> Option<IpAddr> {
        let response_layer_index = response
            .iter()
            .position(|layer| layer.protocol_id().as_str() == self.protocol)?;
        network_endpoints_before(response, response_layer_index).map(|endpoints| endpoints.source)
    }
}

fn tcp_payload_length(packet: &Packet, tcp_layer_index: usize) -> Option<u32> {
    if let Some(encoded_length) = packet.encoded_payload_length(tcp_layer_index) {
        let trailing_padding = packet
            .iter()
            .skip(tcp_layer_index + 1)
            .rev()
            .take_while(|layer| layer.protocol_id().as_str() == "padding")
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
        match layer.protocol_id().as_str() {
            "padding" => break,
            "raw" => {
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

#[derive(Clone, Debug)]
pub(crate) struct EchoMatcher {
    protocol: &'static str,
    request_type: u64,
    reply_type: u64,
}

impl EchoMatcher {
    pub(crate) fn v4() -> Self {
        Self {
            protocol: "icmpv4",
            request_type: 8,
            reply_type: 0,
        }
    }

    pub(crate) fn v6() -> Self {
        Self {
            protocol: "icmpv6",
            request_type: 128,
            reply_type: 129,
        }
    }
}

impl ResponseMatcher for EchoMatcher {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult {
        let Some((request_layer_index, request_layer)) = request
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some((response_layer_index, response_layer)) = response
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some(request_endpoints) = network_endpoints_before(request, request_layer_index) else {
            return MatchResult::no_match();
        };
        let Some(response_endpoints) = network_endpoints_before(response, response_layer_index)
        else {
            return MatchResult::no_match();
        };
        if request_endpoints.source != response_endpoints.destination
            || request_endpoints.destination != response_endpoints.source
        {
            return MatchResult::no_match();
        }
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
            .position(|layer| layer.protocol_id().as_str() == self.protocol)?;
        network_endpoints_before(response, response_layer_index).map(|endpoints| endpoints.source)
    }
}

fn network_endpoints_before(packet: &Packet, upper_layer_index: usize) -> Option<NetworkEnvelope> {
    let (network_layer_index, network_layer) = packet
        .iter()
        .enumerate()
        .take(upper_layer_index)
        .rev()
        .find(|(_, layer)| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))?;
    let source = match network_layer.field("source")? {
        FieldValue::Ipv4(value) => IpAddr::V4(value),
        FieldValue::Ipv6(value) => IpAddr::V6(value),
        _ => return None,
    };
    let mut destination = match network_layer.field("destination")? {
        FieldValue::Ipv4(value) => IpAddr::V4(value),
        FieldValue::Ipv6(value) => IpAddr::V6(value),
        _ => return None,
    };
    if let Some(final_segment) = packet
        .iter()
        .skip(network_layer_index + 1)
        .take(upper_layer_index - network_layer_index - 1)
        .find_map(|layer| {
            if layer.protocol_id().as_str() != "ipv6_srh" {
                return None;
            }
            let FieldValue::List(segments) = layer.field("segments")? else {
                return None;
            };
            segments.last().and_then(|segment| match segment {
                FieldValue::Ipv6(value) => Some(IpAddr::V6(*value)),
                _ => None,
            })
        })
    {
        destination = final_segment;
    }
    Some(NetworkEnvelope {
        source,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;
    use crate::packet::internal::Raw;
    use crate::protocol::internal::{Icmpv4, Ipv4, Ipv6, SegmentRoutingHeader, Tcp, Udp};

    fn echo(source: Ipv4Addr, destination: Ipv4Addr, icmp_type: u8) -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Icmpv4 {
                icmp_type,
                body: Bytes::from_static(&[0x12, 0x34, 0, 7]),
                ..Icmpv4::default()
            });
        packet
    }

    #[test]
    fn echo_matcher_requires_reversed_network_endpoints() {
        let request = echo(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 8);
        let unrelated = echo(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 1), 0);
        let response = echo(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 0);

        assert!(!EchoMatcher::v4().matches(&request, &unrelated).matched);
        assert!(EchoMatcher::v4().matches(&request, &response).matched);
    }

    #[test]
    fn reverse_tuple_uses_srh_final_destination() {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let first: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let mut request = Packet::new();
        request
            .push(Ipv6 {
                source,
                destination: first,
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![first, final_destination],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp {
                source_port: 12345,
                destination_port: 9,
                ..Udp::default()
            });
        let mut response = Packet::new();
        response
            .push(Ipv6 {
                source: final_destination,
                destination: source,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 9,
                destination_port: 12345,
                ..Udp::default()
            });

        let matcher = ReverseFlowMatcher::new("udp");
        assert!(matcher.matches(&request, &response).matched);
        assert_eq!(
            matcher.responder(&request, &response),
            Some(IpAddr::V6(final_destination))
        );
    }

    #[test]
    fn reverse_tuple_uses_network_envelope_nearest_transport() {
        let outer_source = address("2001:db8::1");
        let outer_destination = address("2001:db8::2");
        let inner_source = address("2001:db8:1::1");
        let inner_destination = address("2001:db8:1::2");
        let mut request = Packet::new();
        request
            .push(Ipv6 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv6::default()
            })
            .push(Ipv6 {
                source: inner_source,
                destination: inner_destination,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 12_345,
                destination_port: 9,
                ..Udp::default()
            });
        let mut response = Packet::new();
        response
            // The outer tunnel endpoints are deliberately unrelated. The
            // UDP response belongs to the encapsulated network envelope.
            .push(Ipv6 {
                source: address("2001:db8:ffff::1"),
                destination: address("2001:db8:ffff::2"),
                ..Ipv6::default()
            })
            .push(Ipv6 {
                source: inner_destination,
                destination: inner_source,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 9,
                destination_port: 12_345,
                ..Udp::default()
            });

        let matcher = ReverseFlowMatcher::new("udp");
        assert!(matcher.matches(&request, &response).matched);
        assert_eq!(
            matcher.responder(&request, &response),
            Some(IpAddr::V6(inner_destination))
        );
    }

    fn address(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    fn tcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
    ) -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Tcp {
                source_port: if source.octets()[3] == 1 { 40_000 } else { 443 },
                destination_port: if source.octets()[3] == 1 { 443 } else { 40_000 },
                sequence,
                acknowledgment,
                flags,
                ..Tcp::default()
            });
        packet
    }

    #[test]
    fn tcp_matcher_uses_acknowledgment_and_rst_sequence_state() {
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(10, 0, 0, 2);
        let request = tcp_packet(client, server, 100, 0, Tcp::SYN);
        let matcher = ReverseFlowMatcher::new("tcp");

        let valid_syn_ack = tcp_packet(server, client, 500, 101, Tcp::SYN | Tcp::ACK);
        let wrong_syn_ack = tcp_packet(server, client, 500, 102, Tcp::SYN | Tcp::ACK);
        let valid_ack_rst = tcp_packet(server, client, 0, 101, Tcp::RST | Tcp::ACK);
        let wrong_ack_rst = tcp_packet(server, client, 0, 102, Tcp::RST | Tcp::ACK);
        let valid_bare_rst = tcp_packet(server, client, 0, 0, Tcp::RST);
        let wrong_bare_rst = tcp_packet(server, client, 1, 0, Tcp::RST);

        for response in [valid_syn_ack, valid_ack_rst, valid_bare_rst] {
            assert!(matcher.matches(&request, &response).matched);
        }
        for response in [wrong_syn_ack, wrong_ack_rst, wrong_bare_rst] {
            assert!(!matcher.matches(&request, &response).matched);
        }
    }

    #[test]
    fn tcp_matcher_includes_payload_bytes_in_expected_acknowledgment() {
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(10, 0, 0, 2);
        let mut request = tcp_packet(client, server, u32::MAX - 2, 0, Tcp::SYN);
        request.push(Raw::new(Bytes::from_static(b"data")));
        let matcher = ReverseFlowMatcher::new("tcp");

        // Four data bytes plus SYN consume five sequence numbers and wrap.
        let valid = tcp_packet(server, client, 500, 2, Tcp::SYN | Tcp::ACK);
        let payload_omitted = tcp_packet(server, client, 500, u32::MAX - 1, Tcp::SYN | Tcp::ACK);

        assert!(matcher.matches(&request, &valid).matched);
        assert!(!matcher.matches(&request, &payload_omitted).matched);
    }

    #[test]
    fn reordered_same_tuple_tcp_replies_match_only_their_own_probe() {
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(10, 0, 0, 2);
        let requests =
            [100, 200, 300].map(|sequence| tcp_packet(client, server, sequence, 0, Tcp::SYN));
        let responses = [300, 100, 200]
            .map(|sequence| tcp_packet(server, client, 500, sequence + 1, Tcp::SYN | Tcp::ACK));
        let matcher = ReverseFlowMatcher::new("tcp");

        for (response, expected_sequence) in responses.iter().zip([300, 100, 200]) {
            let matches = requests
                .iter()
                .enumerate()
                .filter_map(|(index, request)| {
                    matcher.matches(request, response).matched.then_some(index)
                })
                .collect::<Vec<_>>();
            assert_eq!(matches, vec![expected_sequence / 100 - 1]);
        }
    }
}
