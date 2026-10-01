// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::{Tcp, Udp},
};
use packetcraftr_core::{packet::Packet, protocol::BuiltinProtocol};

use crate::correlation::{
    icmp_identity, nonzero_ipv4_identification, packet_shape_matches,
    packet_shape_with_payload_matches,
};
use crate::traceroute::MAX_DSCP;

use super::Probe;
use crate::probe::ProbeEndpoint;

pub(in crate::traceroute) fn probe_packet(probe: &Probe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                ttl: probe.hop_limit,
                dscp_ecn: traffic_class(probe.dscp),
                dont_fragment: probe.dont_fragment,
                identification: nonzero_ipv4_identification(u64::from(
                    probe.hop_limit.saturating_sub(1),
                )),
                ..Ipv4::default()
            });
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                hop_limit: probe.hop_limit,
                traffic_class: traffic_class(probe.dscp),
                flow_label: u32::from(probe.hop_limit),
                ..Ipv6::default()
            });
        }
    }
    match probe.target {
        ProbeEndpoint::Udp { port } => {
            packet.push(Udp {
                source_port: probe.source_port,
                destination_port: port,
                ..Udp::default()
            });
            if probe.payload_size > 0 {
                packet.push(Raw::new(vec![0_u8; usize::from(probe.payload_size)]));
            }
        }
        ProbeEndpoint::Tcp { port } => {
            packet.push(Tcp {
                source_port: probe.source_port,
                destination_port: port,
                sequence: probe.sequence as u32,
                flags: Tcp::SYN,
                ..Tcp::default()
            });
        }
        ProbeEndpoint::Icmp => match probe.address {
            IpAddr::V4(_) => {
                packet.push(Icmpv4 {
                    body: icmp_body(probe),
                    ..Icmpv4::default()
                });
            }
            IpAddr::V6(_) => {
                packet.push(Icmpv6 {
                    body: icmp_body(probe),
                    ..Icmpv6::default()
                });
            }
        },
    }
    packet
}

/// Second byte of every traceroute ICMP echo payload; see [`icmp_identity`].
const ICMP_IDENTITY_TAG: u8 = 0x54;

// DSCP occupies the upper six bits of the IPv4 TOS octet and the IPv6 traffic class; ECN stays 0.
// Masking keeps an out-of-range library value from spilling past the six DSCP bits.
const fn traffic_class(dscp: u8) -> u8 {
    (dscp & MAX_DSCP) << 2
}

// The echo body is the probe identity followed by `payload_size` zero bytes.
fn icmp_body(probe: &Probe) -> Bytes {
    let identity = icmp_identity(ICMP_IDENTITY_TAG, probe.sequence);
    if probe.payload_size == 0 {
        return identity;
    }
    let mut body = identity.to_vec();
    body.resize(body.len() + usize::from(probe.payload_size), 0);
    Bytes::from(body)
}

// the observed packet is compared against the same reduction probe_packet applied, so the narrowing
// is symmetric on both sides of the comparison
pub(in crate::traceroute) fn sent_probe_matches(probe: &Probe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let transport_protocol = match probe.target {
        ProbeEndpoint::Tcp { .. } => BuiltinProtocol::Tcp,
        ProbeEndpoint::Udp { .. } => BuiltinProtocol::Udp,
        ProbeEndpoint::Icmp if probe.address.is_ipv4() => BuiltinProtocol::Icmpv4,
        ProbeEndpoint::Icmp => BuiltinProtocol::Icmpv6,
    };
    let expected = [network_protocol, transport_protocol];
    let udp_payload = matches!(probe.target, ProbeEndpoint::Udp { .. }) && probe.payload_size > 0;
    let shape_matches = if udp_payload {
        packet_shape_with_payload_matches(sent, &expected)
    } else {
        packet_shape_matches(sent, &expected)
    };
    if !shape_matches {
        return false;
    }
    if udp_payload
        && !sent.iter().last().is_some_and(|layer| {
            layer.downcast_ref::<Raw>().is_some_and(|raw| {
                raw.bytes.len() == usize::from(probe.payload_size)
                    && raw.bytes.iter().all(|byte| *byte == 0)
            })
        })
    {
        return false;
    }
    let network_matches = match probe.address {
        IpAddr::V4(destination) => {
            sent.iter()
                .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ipv4))
                .count()
                == 1
                && sent.get::<Ipv4>().is_some_and(|ipv4| {
                    ipv4.destination == destination
                        && ipv4.identification
                            == nonzero_ipv4_identification(u64::from(
                                probe.hop_limit.saturating_sub(1),
                            ))
                        && ipv4.ttl == probe.hop_limit
                        && ipv4.dscp_ecn == traffic_class(probe.dscp)
                        && ipv4.dont_fragment == probe.dont_fragment
                })
        }
        IpAddr::V6(destination) => {
            sent.iter()
                .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ipv6))
                .count()
                == 1
                && sent.get::<Ipv6>().is_some_and(|ipv6| {
                    ipv6.destination == destination
                        && ipv6.flow_label == u32::from(probe.hop_limit)
                        && ipv6.hop_limit == probe.hop_limit
                        && ipv6.traffic_class == traffic_class(probe.dscp)
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.target {
        ProbeEndpoint::Udp { port } => sent.get::<Udp>().is_some_and(|udp| {
            udp.source_port == probe.source_port && udp.destination_port == port
        }),
        ProbeEndpoint::Tcp { port } => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.source_port == probe.source_port
                && tcp.destination_port == port
                && tcp.sequence == probe.sequence as u32
                && tcp.flags == Tcp::SYN
        }),
        ProbeEndpoint::Icmp => match probe.address {
            IpAddr::V4(_) => sent.get::<Icmpv4>().is_some_and(|icmp| {
                icmp.icmp_type == 8 && icmp.code == 0 && icmp.body == icmp_body(probe)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128 && icmp.code == 0 && icmp.body == icmp_body(probe)
            }),
        },
    }
}
