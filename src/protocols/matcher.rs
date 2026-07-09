// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::core::{FieldValue, MatchResult, Packet, ResponseMatcher};

#[derive(Clone, Debug)]
pub(crate) struct ReverseTupleMatcher {
    protocol: &'static str,
}

impl ReverseTupleMatcher {
    pub(crate) fn new(protocol: &'static str) -> Self {
        Self { protocol }
    }
}

impl ResponseMatcher for ReverseTupleMatcher {
    fn matches(&self, request: &Packet, response: &Packet) -> MatchResult {
        let Some((request_source, request_destination)) = ip_tuple(request) else {
            return MatchResult::no_match();
        };
        let Some((response_source, response_destination)) = ip_tuple(response) else {
            return MatchResult::no_match();
        };
        if request_source != response_destination || request_destination != response_source {
            return MatchResult::no_match();
        }
        let Some(request_layer) = request
            .iter()
            .find(|layer| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some(response_layer) = response
            .iter()
            .find(|layer| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let ports = |layer: &dyn crate::core::Layer| {
            Some((
                layer.field("source_port")?.as_u64()?,
                layer.field("destination_port")?.as_u64()?,
            ))
        };
        let Some((request_source_port, request_destination_port)) = ports(request_layer) else {
            return MatchResult::no_match();
        };
        let Some((response_source_port, response_destination_port)) = ports(response_layer) else {
            return MatchResult::no_match();
        };
        if request_source_port == response_destination_port
            && request_destination_port == response_source_port
        {
            MatchResult::matched(100, format!("reverse {} tuple", self.protocol))
        } else {
            MatchResult::no_match()
        }
    }
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
        let Some((request_source, request_destination)) = ip_tuple(request) else {
            return MatchResult::no_match();
        };
        let Some((response_source, response_destination)) = ip_tuple(response) else {
            return MatchResult::no_match();
        };
        if request_source != response_destination || request_destination != response_source {
            return MatchResult::no_match();
        }
        let Some(request_layer) = request
            .iter()
            .find(|layer| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
        let Some(response_layer) = response
            .iter()
            .find(|layer| layer.protocol_id().as_str() == self.protocol)
        else {
            return MatchResult::no_match();
        };
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
}

fn ip_tuple(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    let (source, mut destination) = packet.iter().find_map(|layer| {
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
        Some((source, destination))
    })?;
    if let Some(final_segment) = packet.iter().find_map(|layer| {
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
    }) {
        destination = final_segment;
    }
    Some((source, destination))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;
    use crate::protocols::{Icmpv4, Ipv4, Ipv6, SegmentRoutingHeader, Udp};

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

        assert!(
            ReverseTupleMatcher::new("udp")
                .matches(&request, &response)
                .matched
        );
    }
}
