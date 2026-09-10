// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact scan probe construction and sent-packet identity validation.

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};
use packetcraftr_core::{packet::Packet, protocol::BuiltinProtocol};

use crate::probe::{
    EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port, nonzero_ipv4_identification,
    packet_shape_matches,
};

use super::{Probe, ProbeEndpoint};

fn scan_udp_source_port(attempt: u32) -> u16 {
    ephemeral_source_port(
        EPHEMERAL_SOURCE_PORT_BASE,
        u64::from(attempt.saturating_sub(1)),
    )
}

// the operation-local sequence is reduced to the 32-bit and 20-bit wire fields the probe carries;
// sent_probe_matches applies the same reduction when comparing, so even a wrapped counter still
// matches
pub(super) fn probe_packet(probe: &Probe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                identification: nonzero_ipv4_identification(probe.sequence),
                ..Ipv4::default()
            });
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                flow_label: (probe.sequence as u32) & 0x000f_ffff,
                ..Ipv6::default()
            });
        }
    }
    match probe.endpoint {
        ProbeEndpoint::Tcp { port } => packet.push(Tcp {
            destination_port: port,
            sequence: probe.sequence as u32,
            ..Tcp::default()
        }),
        ProbeEndpoint::Udp { port } => {
            packet.push(Udp {
                source_port: scan_udp_source_port(probe.attempt),
                destination_port: port,
                ..Udp::default()
            });
            if !probe.udp_payload.is_empty() {
                // Strict UDP construction checks that the child agrees with
                // its registered port. Retain valid DNS as an exact wire layer;
                // malformed known-protocol payloads still fail strict building.
                if port == 53
                    && let Ok(dns) = Dns::from_wire(probe.udp_payload.clone())
                {
                    packet.push(dns);
                } else {
                    packet.push(Raw::new(probe.udp_payload.clone()));
                }
            }
            &mut packet
        }
        ProbeEndpoint::Icmp => match probe.address {
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

// the identity tag is a deliberate 16-bit reduction of the sequence, split across the two payload
// bytes below
fn icmp_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x43, (sequence >> 8) as u8, sequence as u8])
}

// the observed packet is compared against the same reduction probe_packet applied, so the narrowing
// is symmetric on both sides of the comparison
pub(super) fn sent_probe_matches(probe: &Probe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let transport_protocol = match probe.endpoint {
        ProbeEndpoint::Tcp { .. } => BuiltinProtocol::Tcp,
        ProbeEndpoint::Udp { .. } => BuiltinProtocol::Udp,
        ProbeEndpoint::Icmp if probe.address.is_ipv4() => BuiltinProtocol::Icmpv4,
        ProbeEndpoint::Icmp => BuiltinProtocol::Icmpv6,
    };
    let shape_matches =
        if matches!(probe.endpoint, ProbeEndpoint::Udp { .. }) && !probe.udp_payload.is_empty() {
            (packet_shape_matches(
                sent,
                &[network_protocol, transport_protocol, BuiltinProtocol::Raw],
            ) && sent
                .get::<Raw>()
                .is_some_and(|raw| raw.bytes == probe.udp_payload))
                || (packet_shape_matches(
                    sent,
                    &[network_protocol, transport_protocol, BuiltinProtocol::Dns],
                ) && sent
                    .get::<Dns>()
                    .is_some_and(|dns| dns.wire() == &probe.udp_payload))
        } else {
            probe.udp_payload.is_empty()
                && packet_shape_matches(sent, &[network_protocol, transport_protocol])
        };
    if !shape_matches {
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
                        && ipv4.identification == nonzero_ipv4_identification(probe.sequence)
                })
        }
        IpAddr::V6(destination) => {
            sent.iter()
                .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ipv6))
                .count()
                == 1
                && sent.get::<Ipv6>().is_some_and(|ipv6| {
                    ipv6.destination == destination
                        && ipv6.flow_label == (probe.sequence as u32) & 0x000f_ffff
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.endpoint {
        ProbeEndpoint::Tcp { port } => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.destination_port == port
                && tcp.sequence == probe.sequence as u32
                && tcp.flags == Tcp::SYN
        }),
        ProbeEndpoint::Udp { port } => sent.get::<Udp>().is_some_and(|udp| {
            udp.source_port == scan_udp_source_port(probe.attempt) && udp.destination_port == port
        }),
        ProbeEndpoint::Icmp => match probe.address {
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

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{
        build, codec, decode,
        frame::{Frame, LinkType},
        protocol::builtin,
    };

    #[test]
    fn dns_payloads_use_the_exact_dns_layer_under_strict_port_binding() {
        let payload =
            crate::dns::encode_query("example.test", crate::dns::QueryType::A, 1234, true, None)
                .unwrap();
        let probe = Probe {
            sequence: 0,
            attempt: 1,
            address: "192.0.2.53".parse().unwrap(),
            endpoint: ProbeEndpoint::Udp { port: 53 },
            udp_payload: payload.clone(),
        };
        let mut packet = probe.packet();
        packet.get_mut::<Ipv4>().unwrap().source = "192.0.2.1".parse().unwrap();
        let built = build::Builder::new(builtin::registry())
            .build(packet, codec::Context::default(), build::Options::default())
            .unwrap();
        assert!(built.bytes.ends_with(&payload));
        assert!(sent_probe_matches(&probe, &built.packet));
        assert_eq!(built.packet.get::<Dns>().unwrap().wire(), &payload);
        let mut changed = probe.clone();
        changed.udp_payload =
            crate::dns::encode_query("other.test", crate::dns::QueryType::A, 1234, true, None)
                .unwrap();
        assert!(!sent_probe_matches(&changed, &built.packet));
    }

    #[test]
    fn udp_payload_round_trips_with_valid_ipv4_and_ipv6_checksums_and_correlated_replies() {
        let registry = builtin::registry();
        for (source, address, link) in [
            ("192.0.2.1", "192.0.2.2", LinkType::IPV4),
            ("2001:db8::1", "2001:db8::2", LinkType::IPV6),
        ] {
            let source: IpAddr = source.parse().unwrap();
            let probe = Probe {
                sequence: 4,
                attempt: 1,
                address: address.parse().unwrap(),
                endpoint: ProbeEndpoint::Udp { port: 50001 },
                udp_payload: Bytes::from_static(b"\x00query\xff"),
            };
            let mut packet = probe.packet();
            match source {
                IpAddr::V4(source) => packet.get_mut::<Ipv4>().unwrap().source = source,
                IpAddr::V6(source) => packet.get_mut::<Ipv6>().unwrap().source = source,
            }
            let built = build::Builder::new(registry.clone())
                .build(packet, codec::Context::default(), build::Options::default())
                .unwrap();
            assert!(built.bytes.ends_with(&probe.udp_payload));
            assert!(sent_probe_matches(&probe, &built.packet));
            let frame = Frame::new(std::time::UNIX_EPOCH, link, built.bytes.clone()).unwrap();
            let decoded = decode::Dissector::new(registry.clone())
                .decode(frame, decode::Options::default())
                .unwrap();
            assert!(
                !decoded
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.is_checksum_failure())
            );
            assert_eq!(
                decoded.packet.get::<Raw>().unwrap().bytes,
                probe.udp_payload
            );
            let mut reply = built.packet.clone();
            if let Some(ip) = reply.get_mut::<Ipv4>() {
                std::mem::swap(&mut ip.source, &mut ip.destination);
                ip.checksum = packetcraftr_core::field::WireValue::Auto;
            }
            if let Some(ip) = reply.get_mut::<Ipv6>() {
                std::mem::swap(&mut ip.source, &mut ip.destination);
            }
            let udp = reply.get_mut::<Udp>().unwrap();
            std::mem::swap(&mut udp.source_port, &mut udp.destination_port);
            udp.checksum = packetcraftr_core::field::WireValue::Auto;
            let reply = build::Builder::new(registry.clone())
                .build(reply, codec::Context::default(), build::Options::default())
                .unwrap();
            let response = decode::Dissector::new(registry.clone())
                .decode(
                    Frame::new(std::time::UNIX_EPOCH, link, reply.bytes).unwrap(),
                    decode::Options::default(),
                )
                .unwrap();
            assert_eq!(
                crate::scan::classify_response(
                    &registry,
                    crate::scan::Transport::Udp,
                    &built.packet,
                    &response
                )
                .unwrap()
                .classification,
                crate::scan::Classification::Open
            );
        }
    }
}
