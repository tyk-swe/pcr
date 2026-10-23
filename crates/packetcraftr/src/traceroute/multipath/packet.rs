// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Flow, Request};
use crate::probe::Transport;
use bytes::Bytes;
use packetcraftr_core::{
    decode::DecodedPacket,
    field::WireValue,
    layer::Raw,
    packet::Packet,
    protocol::{
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        quoted_probe,
        transport::{Tcp, Udp},
    },
    registry::Registry,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) const UDP_IDENTITY_BYTES: usize = 16;
pub(super) const MAX_IDENTITY_BYTES: u64 = 18;

#[derive(Clone)]
pub(super) struct Probe {
    pub sequence: u64,
    pub flow: Flow,
    pub sweep: u32,
    pub hop: u8,
    pub packet: Packet,
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub(super) fn flows(request: &Request, destination: IpAddr, nonce: u64) -> Vec<Flow> {
    let width = u32::from(u16::MAX) - 49_152 + 1 - u32::from(request.flows) + 1;
    let base = request
        .trace
        .source_port
        .unwrap_or((49_152 + (nonce as u32 % width)) as u16);
    (0..request.flows)
        .map(|index| Flow {
            id: index + 1,
            destination,
            strategy: request.trace.strategy,
            source: if destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            source_port: (request.trace.strategy != Transport::Icmp).then_some(base + index),
            destination_port: request.trace.destination_port,
            icmp_identifier: (request.trace.strategy == Transport::Icmp)
                .then_some((nonce as u16).wrapping_add(index)),
            ipv6_flow_label: destination
                .is_ipv6()
                .then_some((((nonce as u32).wrapping_add(u32::from(index))) % 0x000f_ffff) + 1),
        })
        .collect()
}

impl Probe {
    pub(super) fn new(
        request: &Request,
        flow: Flow,
        destination: IpAddr,
        nonce: u64,
        sweep: u32,
        hop: u8,
    ) -> Self {
        let offset = u64::from(sweep - 1) * request.trace.hop_count() as u64
            + u64::from(hop - request.trace.first_hop);
        let sequence = offset * u64::from(request.flows) + u64::from(flow.id - 1);
        // At most 255 * 32 probes per flow: no identity repeats within a run.
        let token = ((nonce % 65_535 + offset) % 65_535 + 1) as u16;
        let mut packet = Packet::new();
        match destination {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    source: match flow.source {
                        IpAddr::V4(source) => source,
                        _ => Ipv4Addr::UNSPECIFIED,
                    },
                    destination,
                    ttl: hop,
                    identification: token,
                    dscp_ecn: request.trace.dscp << 2,
                    dont_fragment: request.trace.dont_fragment,
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    source: match flow.source {
                        IpAddr::V6(source) => source,
                        _ => Ipv6Addr::UNSPECIFIED,
                    },
                    destination,
                    hop_limit: hop,
                    flow_label: flow.ipv6_flow_label.unwrap_or_default(),
                    traffic_class: request.trace.dscp << 2,
                    ..Ipv6::default()
                });
            }
        }
        let mut tag = Vec::from(*b"PCMP");
        tag.extend_from_slice(&nonce.to_be_bytes());
        match request.trace.strategy {
            Transport::Udp => {
                tag.extend_from_slice(&token.to_be_bytes());
                tag.extend_from_slice(&(!token).to_be_bytes());
                tag.resize(tag.len() + usize::from(request.trace.payload_size), 0);
                packet.push(Udp {
                    source_port: flow.source_port.unwrap(),
                    destination_port: flow.destination_port.unwrap(),
                    ..Udp::default()
                });
                packet.push(Raw::new(tag));
            }
            Transport::Tcp => {
                packet.push(Tcp {
                    source_port: flow.source_port.unwrap(),
                    destination_port: flow.destination_port.unwrap(),
                    sequence: (nonce as u32).wrapping_add(sequence as u32),
                    flags: Tcp::SYN,
                    ..Tcp::default()
                });
            }
            Transport::Icmp => {
                let mut body = Vec::from(flow.icmp_identifier.unwrap().to_be_bytes());
                body.extend_from_slice(&token.to_be_bytes());
                body.extend_from_slice(&tag);
                body.extend_from_slice(&(!token).to_be_bytes());
                body.resize(body.len() + usize::from(request.trace.payload_size), 0);
                if destination.is_ipv4() {
                    packet.push(Icmpv4 {
                        body: Bytes::from(body),
                        ..Icmpv4::default()
                    });
                } else {
                    packet.push(Icmpv6 {
                        body: Bytes::from(body),
                        ..Icmpv6::default()
                    });
                }
            }
            _ => unreachable!("validated traceroute strategy"),
        }
        Self {
            sequence,
            flow,
            sweep,
            hop,
            packet,
        }
    }
}

fn raw(packet: &Packet) -> Option<&[u8]> {
    packet.get::<Raw>().map(|raw| raw.bytes.as_ref())
}

pub(super) fn sent_matches(probe: &Probe, sent: &Packet) -> bool {
    use crate::engine::correlation::{packet_shape_matches, packet_shape_with_payload_matches};
    use packetcraftr_core::protocol::BuiltinProtocol;
    let net = if probe.packet.get::<Ipv4>().is_some() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let transport = if probe.packet.get::<Udp>().is_some() {
        BuiltinProtocol::Udp
    } else if probe.packet.get::<Tcp>().is_some() {
        BuiltinProtocol::Tcp
    } else if probe.packet.get::<Icmpv4>().is_some() {
        BuiltinProtocol::Icmpv4
    } else {
        BuiltinProtocol::Icmpv6
    };
    let expected = [net, transport];
    let shape = if transport == BuiltinProtocol::Udp {
        packet_shape_with_payload_matches(sent, &expected)
    } else {
        packet_shape_matches(sent, &expected)
    };
    if !shape {
        return false;
    }
    let network = if let Some(expected) = probe.packet.get::<Ipv4>() {
        sent.get::<Ipv4>().is_some_and(|actual| {
            actual.destination == expected.destination
                && (expected.source.is_unspecified() || actual.source == expected.source)
                && actual.ttl == expected.ttl
                && actual.identification == expected.identification
                && actual.dscp_ecn == expected.dscp_ecn
                && actual.dont_fragment == expected.dont_fragment
        })
    } else {
        let expected = probe.packet.get::<Ipv6>().unwrap();
        sent.get::<Ipv6>().is_some_and(|actual| {
            actual.destination == expected.destination
                && (expected.source.is_unspecified() || actual.source == expected.source)
                && actual.hop_limit == expected.hop_limit
                && actual.flow_label == expected.flow_label
                && actual.traffic_class == expected.traffic_class
        })
    };
    network
        && if let Some(expected) = probe.packet.get::<Udp>() {
            sent.get::<Udp>().is_some_and(|actual| {
                actual.source_port == expected.source_port
                    && actual.destination_port == expected.destination_port
            }) && raw(sent) == raw(&probe.packet)
        } else if let Some(expected) = probe.packet.get::<Tcp>() {
            sent.get::<Tcp>().is_some_and(|actual| {
                actual.source_port == expected.source_port
                    && actual.destination_port == expected.destination_port
                    && actual.sequence == expected.sequence
                    && actual.flags == expected.flags
            })
        } else if let Some(expected) = probe.packet.get::<Icmpv4>() {
            sent.get::<Icmpv4>().is_some_and(|actual| {
                actual.body == expected.body
                    && actual.icmp_type == expected.icmp_type
                    && actual.code == expected.code
            })
        } else {
            let expected = probe.packet.get::<Icmpv6>().unwrap();
            sent.get::<Icmpv6>().is_some_and(|actual| {
                actual.body == expected.body
                    && actual.icmp_type == expected.icmp_type
                    && actual.code == expected.code
            })
        }
}

pub(super) fn classify(
    registry: &Registry,
    strategy: Transport,
    sent: &Packet,
    response: &DecodedPacket,
) -> Option<crate::traceroute::CorrelatedResponse> {
    let result = crate::traceroute::classify_response(registry, strategy, sent, response)?;
    if let Some(quote) = quoted_probe(&response.packet) {
        if let Some(ip) = sent.get::<Ipv4>() {
            if quote.ipv4_identification != Some(ip.identification) {
                return None;
            }
        } else if quote.ipv6_flow_label != sent.get::<Ipv6>().map(|ip| ip.flow_label) {
            return None;
        }
        if strategy == Transport::Udp {
            let udp = sent.get::<Udp>()?;
            let WireValue::Exact(checksum) = udp.checksum else {
                return None;
            };
            let WireValue::Exact(length) = udp.length else {
                return None;
            };
            if quote.payload.get(4..6)? != length.to_be_bytes()
                || quote.payload.get(6..8)? != checksum.to_be_bytes()
            {
                return None;
            }
            let expected = raw(sent)?.get(..UDP_IDENTITY_BYTES)?;
            let quoted = quote.payload.get(8..)?;
            if sent.get::<Ipv6>().is_some() && quoted.len() < expected.len() {
                return None;
            }
            let available = quoted.len().min(expected.len());
            if quoted[..available] != expected[..available] {
                return None;
            }
        }
    } else if strategy == Transport::Udp {
        if raw(&response.packet)?.get(..UDP_IDENTITY_BYTES)?
            != raw(sent)?.get(..UDP_IDENTITY_BYTES)?
        {
            return None;
        }
    } else if strategy == Transport::Icmp {
        let expected = sent
            .get::<Icmpv4>()
            .map(|icmp| &icmp.body)
            .or_else(|| sent.get::<Icmpv6>().map(|icmp| &icmp.body))?;
        let actual = response
            .packet
            .get::<Icmpv4>()
            .map(|icmp| &icmp.body)
            .or_else(|| response.packet.get::<Icmpv6>().map(|icmp| &icmp.body))?;
        if actual != expected {
            return None;
        }
    }
    Some(result)
}

pub(super) fn reset(sent: &Packet, response: &DecodedPacket) -> Option<Packet> {
    let reply = response.packet.get::<Tcp>()?;
    if reply.flags & (Tcp::SYN | Tcp::ACK | Tcp::RST) != Tcp::SYN | Tcp::ACK {
        return None;
    }
    let tcp = sent.get::<Tcp>()?;
    let mut packet = Packet::new();
    if let Some(ip) = sent.get::<Ipv4>() {
        packet.push(Ipv4 {
            source: ip.source,
            destination: ip.destination,
            ttl: ip.ttl,
            identification: ip.identification,
            dscp_ecn: ip.dscp_ecn,
            ..Ipv4::default()
        });
    } else {
        let ip = sent.get::<Ipv6>()?;
        packet.push(Ipv6 {
            source: ip.source,
            destination: ip.destination,
            hop_limit: ip.hop_limit,
            flow_label: ip.flow_label,
            traffic_class: ip.traffic_class,
            ..Ipv6::default()
        });
    }
    packet.push(Tcp {
        source_port: tcp.source_port,
        destination_port: tcp.destination_port,
        sequence: reply.acknowledgment,
        flags: Tcp::RST,
        ..Tcp::default()
    });
    Some(packet)
}
