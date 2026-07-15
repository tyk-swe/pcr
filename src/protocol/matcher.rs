// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::{
    Packet,
    codec::NetworkEnvelope,
    field::FieldValue,
    matcher::{MatchResult, ResponseMatcher},
};

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
        let transport = match self.protocol {
            "tcp" => QuotedProbeTransport::Tcp,
            "udp" => QuotedProbeTransport::Udp,
            _ => return MatchResult::no_match(),
        };
        if quoted_icmp_error_kind(request, response, transport).is_some() {
            return MatchResult::matched(150, "matching quoted ICMP error response");
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuotedIcmpError {
    PortUnreachable,
    AdministrativelyProhibited,
    DestinationUnreachable,
    TimeExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuotedProbeTransport {
    Tcp,
    Udp,
    Icmp,
}

/// Identifies an ICMP error that quotes the exact request. The client exchange
/// uses this protocol-layer correlation before workflow-specific classification
/// so it can retain the capture ingress latency.
pub(crate) fn quoted_icmp_error_kind(
    request: &Packet,
    response: &Packet,
    expected_transport: QuotedProbeTransport,
) -> Option<QuotedIcmpError> {
    let transport = request
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "tcp" => Some(QuotedProbeTransport::Tcp),
            "udp" => Some(QuotedProbeTransport::Udp),
            "icmpv4" | "icmpv6" => Some(QuotedProbeTransport::Icmp),
            _ => None,
        })?;
    if transport != expected_transport {
        return None;
    }
    let request_source = outer_network_envelope(request)?.source;
    let response_destination = outer_network_envelope(response)?.destination;
    if request_source != response_destination {
        return None;
    }
    let layer = response
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "icmpv4" | "icmpv6"))?;
    let icmp_type = u8::try_from(layer.field("type")?.as_u64()?).ok()?;
    let code = u8::try_from(layer.field("code")?.as_u64()?).ok()?;
    let FieldValue::Bytes(body) = layer.field("body")? else {
        return None;
    };
    if !quoted_probe_matches(transport, request, body.get(4..)?) {
        return None;
    }
    match layer.protocol_id().as_str() {
        "icmpv4" if icmp_type == 3 => match code {
            3 if transport == QuotedProbeTransport::Udp => Some(QuotedIcmpError::PortUnreachable),
            9 | 10 | 13 => Some(QuotedIcmpError::AdministrativelyProhibited),
            _ => Some(QuotedIcmpError::DestinationUnreachable),
        },
        "icmpv4" if icmp_type == 11 => Some(QuotedIcmpError::TimeExceeded),
        "icmpv6" if icmp_type == 1 => match code {
            4 if transport == QuotedProbeTransport::Udp => Some(QuotedIcmpError::PortUnreachable),
            1 | 5 | 6 => Some(QuotedIcmpError::AdministrativelyProhibited),
            _ => Some(QuotedIcmpError::DestinationUnreachable),
        },
        "icmpv6" if icmp_type == 3 => Some(QuotedIcmpError::TimeExceeded),
        _ => None,
    }
}

fn quoted_probe_matches(transport: QuotedProbeTransport, request: &Packet, quote: &[u8]) -> bool {
    let Some(quoted) = parse_quoted_probe(quote) else {
        return false;
    };
    let Some(network) = outer_network_envelope(request) else {
        return false;
    };
    if quoted.source != network.source || quoted.destination != network.destination {
        return false;
    }
    match transport {
        QuotedProbeTransport::Tcp | QuotedProbeTransport::Udp => {
            let (protocol_name, protocol_number) = if transport == QuotedProbeTransport::Tcp {
                ("tcp", 6)
            } else {
                ("udp", 17)
            };
            if quoted.protocol != protocol_number {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == protocol_name)
            else {
                return false;
            };
            let Some(source_port) = layer
                .field("source_port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
            else {
                return false;
            };
            let Some(destination_port) = layer
                .field("destination_port")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
            else {
                return false;
            };
            let source_port = source_port.to_be_bytes();
            let destination_port = destination_port.to_be_bytes();
            if quoted.payload.get(..4)
                != Some(
                    &[
                        source_port[0],
                        source_port[1],
                        destination_port[0],
                        destination_port[1],
                    ][..],
                )
            {
                return false;
            }
            if transport == QuotedProbeTransport::Tcp {
                let Some(sequence) = layer
                    .field("sequence")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                else {
                    return false;
                };
                quoted.payload.get(4..8) == Some(&sequence.to_be_bytes()[..])
            } else {
                true
            }
        }
        QuotedProbeTransport::Icmp => {
            let (protocol, name) = if network.source.is_ipv4() {
                (1, "icmpv4")
            } else {
                (58, "icmpv6")
            };
            if quoted.protocol != protocol {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == name)
            else {
                return false;
            };
            let Some(icmp_type) = layer
                .field("type")
                .and_then(|value| value.as_u64())
                .and_then(|value| u8::try_from(value).ok())
            else {
                return false;
            };
            let Some(code) = layer
                .field("code")
                .and_then(|value| value.as_u64())
                .and_then(|value| u8::try_from(value).ok())
            else {
                return false;
            };
            let Some(FieldValue::Bytes(body)) = layer.field("body") else {
                return false;
            };
            quoted.payload.len() >= 8
                && quoted.payload[0] == icmp_type
                && quoted.payload[1] == code
                && body.len() >= 4
                && quoted.payload[4..8] == body[..4]
        }
    }
}

struct QuotedProbe<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

fn parse_quoted_probe(bytes: &[u8]) -> Option<QuotedProbe<'_>> {
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let header_len = usize::from(bytes[0] & 0x0f).checked_mul(4)?;
            if header_len < 20 || bytes.len() < header_len + 8 {
                return None;
            }
            let total_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if total_length < header_len + 8 {
                return None;
            }
            let fragment_offset = u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                destination: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                protocol: bytes[9],
                payload: &bytes[header_len..],
            })
        }
        6 => {
            if bytes.len() < 48 {
                return None;
            }
            if u16::from_be_bytes([bytes[4], bytes[5]]) < 8 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                protocol: bytes[6],
                payload: &bytes[40..],
            })
        }
        _ => None,
    }
}

fn outer_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        let source = match layer.field("source")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        let destination = match layer.field("destination")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        Some(NetworkEnvelope {
            source,
            destination,
        })
    })
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
        if quoted_icmp_error_kind(request, response, QuotedProbeTransport::Icmp).is_some() {
            return MatchResult::matched(150, "matching quoted ICMP error response");
        }
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
    use crate::packet::layer::Raw;
    use crate::protocol::{
        icmp::{Icmpv4, Icmpv6},
        ipv6::SegmentRoutingHeader,
        network::{Ipv4, Ipv6},
        transport::{Tcp, Udp},
    };

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
    fn matchers_accept_quoted_icmp_errors_for_each_probe_transport() {
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let destination = Ipv4Addr::new(10, 0, 0, 2);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut udp = Packet::new();
        udp.push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 33_434,
            ..Udp::default()
        });
        let mut tcp = Packet::new();
        tcp.push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 12_345,
            destination_port: 443,
            sequence: 17,
            flags: Tcp::SYN,
            ..Tcp::default()
        });
        let icmp = echo(source, destination, 8);

        assert!(
            ReverseFlowMatcher::new("udp")
                .matches(&udp, &quoted_icmpv4_time_exceeded(router, source, 17, &udp))
                .matched
        );
        assert!(
            ReverseFlowMatcher::new("tcp")
                .matches(&tcp, &quoted_icmpv4_time_exceeded(router, source, 6, &tcp))
                .matched
        );
        assert!(
            EchoMatcher::v4()
                .matches(
                    &icmp,
                    &quoted_icmpv4_time_exceeded(router, source, 1, &icmp)
                )
                .matched
        );
    }

    #[test]
    fn quoted_icmp_errors_require_matching_transport_and_inner_payload_lengths() {
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let destination = Ipv4Addr::new(10, 0, 0, 2);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut request = Packet::new();
        request
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 12_345,
                destination_port: 33_434,
                ..Udp::default()
            });
        let valid = quoted_icmpv4_time_exceeded(router, source, 17, &request);
        assert!(quoted_icmp_error_kind(&request, &valid, QuotedProbeTransport::Udp).is_some());
        assert!(quoted_icmp_error_kind(&request, &valid, QuotedProbeTransport::Tcp).is_none());

        let mut malformed_v4 = valid;
        let mut body = malformed_v4.get::<Icmpv4>().unwrap().body.to_vec();
        body[6..8].copy_from_slice(&0_u16.to_be_bytes());
        malformed_v4.get_mut::<Icmpv4>().unwrap().body = Bytes::from(body);
        assert!(
            quoted_icmp_error_kind(&request, &malformed_v4, QuotedProbeTransport::Udp).is_none()
        );

        let source_v6: Ipv6Addr = "fd00::1".parse().unwrap();
        let destination_v6: Ipv6Addr = "fd00::2".parse().unwrap();
        let router_v6: Ipv6Addr = "fd00::fe".parse().unwrap();
        let mut request_v6 = Packet::new();
        request_v6
            .push(Ipv6 {
                source: source_v6,
                destination: destination_v6,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 12_345,
                destination_port: 33_434,
                ..Udp::default()
            });
        let valid_v6 = quoted_icmpv6_time_exceeded(router_v6, source_v6, &request_v6);
        assert!(
            quoted_icmp_error_kind(&request_v6, &valid_v6, QuotedProbeTransport::Udp).is_some()
        );
        let mut malformed_v6 = valid_v6;
        let mut body = malformed_v6.get::<Icmpv6>().unwrap().body.to_vec();
        body[8..10].copy_from_slice(&0_u16.to_be_bytes());
        malformed_v6.get_mut::<Icmpv6>().unwrap().body = Bytes::from(body);
        assert!(
            quoted_icmp_error_kind(&request_v6, &malformed_v6, QuotedProbeTransport::Udp).is_none()
        );
    }

    fn quoted_icmpv4_time_exceeded(
        router: Ipv4Addr,
        source: Ipv4Addr,
        protocol: u8,
        request: &Packet,
    ) -> Packet {
        let request_network = request.get::<Ipv4>().unwrap();
        let mut quote = vec![0_u8; 28];
        quote[0] = 0x45;
        quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
        quote[9] = protocol;
        quote[12..16].copy_from_slice(&request_network.source.octets());
        quote[16..20].copy_from_slice(&request_network.destination.octets());
        match protocol {
            6 => {
                let tcp = request.get::<Tcp>().unwrap();
                quote[20..22].copy_from_slice(&tcp.source_port.to_be_bytes());
                quote[22..24].copy_from_slice(&tcp.destination_port.to_be_bytes());
                quote[24..28].copy_from_slice(&tcp.sequence.to_be_bytes());
            }
            17 => {
                let udp = request.get::<Udp>().unwrap();
                quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
                quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
            }
            1 => {
                let icmp = request.get::<Icmpv4>().unwrap();
                quote[20] = icmp.icmp_type;
                quote[21] = icmp.code;
                quote[24..28].copy_from_slice(&icmp.body[..4]);
            }
            _ => unreachable!("test only covers registered IPv4 probe transports"),
        }
        let mut body = vec![0_u8; 4];
        body.extend(quote);
        let mut response = Packet::new();
        response
            .push(Ipv4 {
                source: router,
                destination: source,
                ..Ipv4::default()
            })
            .push(Icmpv4 {
                icmp_type: 11,
                body: body.into(),
                ..Icmpv4::default()
            });
        response
    }

    fn quoted_icmpv6_time_exceeded(router: Ipv6Addr, source: Ipv6Addr, request: &Packet) -> Packet {
        let request_network = request.get::<Ipv6>().unwrap();
        let udp = request.get::<Udp>().unwrap();
        let mut quote = vec![0_u8; 48];
        quote[0] = 0x60;
        quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
        quote[6] = 17;
        quote[8..24].copy_from_slice(&request_network.source.octets());
        quote[24..40].copy_from_slice(&request_network.destination.octets());
        quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
        quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
        let mut body = vec![0_u8; 4];
        body.extend(quote);
        let mut response = Packet::new();
        response
            .push(Ipv6 {
                source: router,
                destination: source,
                ..Ipv6::default()
            })
            .push(Icmpv6 {
                icmp_type: 3,
                body: body.into(),
                ..Icmpv6::default()
            });
        response
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
