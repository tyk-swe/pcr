// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact traceroute probe construction and sent-packet identity validation.

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};
use packetcraftr_core::{Packet, protocol::BuiltinProtocol};

use crate::probe::{nonzero_ipv4_identification, packet_shape_matches};

use super::SOURCE_PORT;
use super::model::{Probe, ProbeTarget};

#[expect(
    clippy::cast_possible_truncation,
    reason = "the operation-local sequence is reduced to the 32-bit wire field the probe carries; \
              sent_probe_matches applies the same reduction when comparing, so even a \
              wrapped counter still matches"
)]
pub(super) fn probe_packet(probe: &Probe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                ttl: probe.hop_limit,
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
                flow_label: u32::from(probe.hop_limit),
                ..Ipv6::default()
            });
        }
    }
    match probe.target {
        ProbeTarget::Udp { port } => packet.push(Udp {
            source_port: SOURCE_PORT,
            destination_port: port,
            ..Udp::default()
        }),
        ProbeTarget::Tcp { port } => packet.push(Tcp {
            source_port: SOURCE_PORT,
            destination_port: port,
            sequence: probe.sequence as u32,
            flags: Tcp::SYN,
            ..Tcp::default()
        }),
        ProbeTarget::Icmp => match probe.address {
            IpAddr::V4(_) => packet.push(Icmpv4 {
                body: icmp_identity(probe.sequence),
                ..Icmpv4::default()
            }),
            IpAddr::V6(_) => packet.push(Icmpv6 {
                body: icmp_identity(probe.sequence),
                ..Icmpv6::default()
            }),
        },
    };
    packet
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the identity tag is a deliberate 16-bit reduction of the sequence, split across \
              the two payload bytes below"
)]
pub(super) fn icmp_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x54, (sequence >> 8) as u8, sequence as u8])
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the observed packet is compared against the same reduction probe_packet applied, \
              so the narrowing is symmetric on both sides of the comparison"
)]
pub(super) fn sent_probe_matches(probe: &Probe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let transport_protocol = match probe.target {
        ProbeTarget::Tcp { .. } => BuiltinProtocol::Tcp,
        ProbeTarget::Udp { .. } => BuiltinProtocol::Udp,
        ProbeTarget::Icmp if probe.address.is_ipv4() => BuiltinProtocol::Icmpv4,
        ProbeTarget::Icmp => BuiltinProtocol::Icmpv6,
    };
    if !packet_shape_matches(sent, &[network_protocol, transport_protocol]) {
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
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.target {
        ProbeTarget::Udp { port } => sent
            .get::<Udp>()
            .is_some_and(|udp| udp.source_port == SOURCE_PORT && udp.destination_port == port),
        ProbeTarget::Tcp { port } => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.source_port == SOURCE_PORT
                && tcp.destination_port == port
                && tcp.sequence == probe.sequence as u32
                && tcp.flags == Tcp::SYN
        }),
        ProbeTarget::Icmp => match probe.address {
            IpAddr::V4(_) => sent.get::<Icmpv4>().is_some_and(|icmp| {
                icmp.icmp_type == 8 && icmp.code == 0 && icmp.body == icmp_identity(probe.sequence)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128
                    && icmp.code == 0
                    && icmp.body == icmp_identity(probe.sequence)
            }),
        },
    }
}
