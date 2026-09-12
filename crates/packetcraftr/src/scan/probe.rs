// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact scan probe construction and sent-packet identity validation.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::codec::{self, DecodedLayer, LayerDecodeContext};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::tunnel::Geneve;
use packetcraftr_core::protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{build, decode, packet::Packet, protocol::BuiltinProtocol};

use crate::probe::{
    EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port, nonzero_ipv4_identification,
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
            push_udp_payload(&mut packet, port, &probe.udp_payload);
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

const DNS_PORT: u16 = 53;
const VXLAN_PORT: u16 = 4789;
const GENEVE_PORT: u16 = 6081;
const GENEVE_ETHERNET: u16 = 0x6558;
const GENEVE_IPV4: u16 = 0x0800;
const GENEVE_IPV6: u16 = 0x86dd;

// Strict UDP construction checks that the child agrees with its registered port. DNS, VXLAN, and
// Geneve are the only payload protocols the builtin registry binds, so materialize those as typed
// layers and keep every other payload as exact Raw bytes; a payload that does not decode as its
// registered protocol also stays Raw and fails strict building as before.
fn push_udp_payload(packet: &mut Packet, port: u16, payload: &Bytes) {
    if payload.is_empty() {
        return;
    }
    let registry = builtin::registry();
    if port == DNS_PORT
        && let Ok(dns) = Dns::from_wire(payload.clone())
    {
        packet.push(dns);
        return;
    }
    if port == VXLAN_PORT
        && push_typed_tunnel(
            packet,
            &registry,
            "vxlan",
            LinkType::ETHERNET,
            "ethernet",
            payload,
        )
    {
        return;
    }
    if port == GENEVE_PORT && push_geneve_payload(packet, &registry, payload) {
        return;
    }
    packet.push(Raw::new(payload.clone()));
}

fn decode_tunnel_header(
    registry: &Registry,
    protocol: &str,
    payload: &[u8],
) -> Option<DecodedLayer> {
    registry
        .codec(protocol)?
        .decode(
            payload,
            &LayerDecodeContext {
                registry,
                allow_trailing_padding: false,
                network: None,
                discriminator: None,
            },
        )
        .ok()
}

fn decode_inner(
    registry: &Arc<Registry>,
    link_type: LinkType,
    bytes: &[u8],
) -> Vec<Box<dyn Layer>> {
    let Ok(frame) = Frame::new(
        SystemTime::UNIX_EPOCH,
        link_type,
        Bytes::copy_from_slice(bytes),
    ) else {
        return Vec::new();
    };
    let Ok(decoded) =
        decode::Dissector::new(Arc::clone(registry)).decode(frame, decode::Options::default())
    else {
        return Vec::new();
    };
    decoded
        .packet
        .iter()
        .map(|layer| layer.clone_box())
        .collect()
}

fn push_typed_tunnel(
    packet: &mut Packet,
    registry: &Arc<Registry>,
    protocol: &str,
    link_type: LinkType,
    expected_root: &str,
    payload: &[u8],
) -> bool {
    let Some(header) = decode_tunnel_header(registry, protocol, payload) else {
        return false;
    };
    let inner = decode_inner(registry, link_type, &payload[header.consumed..]);
    if inner
        .first()
        .is_none_or(|layer| layer.protocol_id().as_str() != expected_root)
    {
        return false;
    }
    packet.push_boxed(header.layer);
    for layer in inner {
        packet.push_boxed(layer);
    }
    true
}

fn push_geneve_payload(packet: &mut Packet, registry: &Arc<Registry>, payload: &[u8]) -> bool {
    let Some(header) = decode_tunnel_header(registry, "geneve", payload) else {
        return false;
    };
    let Some(geneve) = header.layer.as_any().downcast_ref::<Geneve>() else {
        return false;
    };
    let inner_bytes = &payload[header.consumed..];
    let (link_type, expected_root, opaque) = match geneve.protocol_type {
        WireValue::Exact(GENEVE_ETHERNET) => (Some(LinkType::ETHERNET), Some("ethernet"), false),
        WireValue::Exact(GENEVE_IPV4) => (Some(LinkType::IPV4), Some("ipv4"), false),
        WireValue::Exact(GENEVE_IPV6) => (Some(LinkType::IPV6), Some("ipv6"), false),
        _ => (None, None, true),
    };
    let inner = link_type.map_or_else(Vec::new, |link| decode_inner(registry, link, inner_bytes));
    if !opaque
        && inner
            .first()
            .is_none_or(|layer| Some(layer.protocol_id().as_str()) != expected_root)
    {
        return false;
    }
    packet.push_boxed(header.layer);
    if opaque {
        packet.push(Raw::new(Bytes::copy_from_slice(inner_bytes)));
    } else {
        for layer in inner {
            packet.push_boxed(layer);
        }
    }
    true
}

// Re-encode the layers after the transport header so the exact UDP payload bytes are compared
// directly, whatever typed or opaque form carries them, without changing the matcher signature used
// by sent-evidence validation.
fn sent_payload_matches(
    probe: &Probe,
    sent: &Packet,
    network_protocol: BuiltinProtocol,
    transport_protocol: BuiltinProtocol,
) -> bool {
    let network_index = usize::from(
        sent.layer(0)
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet)),
    );
    if sent.layer(network_index).and_then(BuiltinProtocol::of) != Some(network_protocol)
        || sent.layer(network_index + 1).and_then(BuiltinProtocol::of) != Some(transport_protocol)
    {
        return false;
    }
    let mut suffix = Packet::new();
    for layer in sent.iter().skip(network_index + 2) {
        suffix.push_boxed(layer.clone_box());
    }
    payload_bytes(&suffix).is_some_and(|bytes| bytes == probe.udp_payload)
}

fn payload_bytes(payload: &Packet) -> Option<Bytes> {
    if payload.is_empty() {
        return Some(Bytes::new());
    }
    build::Builder::new(builtin::registry())
        .build(
            payload.clone(),
            codec::Context::default(),
            build::Options::default(),
        )
        .ok()
        .map(|built| built.bytes)
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
    if !sent_payload_matches(probe, sent, network_protocol, transport_protocol) {
        return false;
    }
    let network_matches = match probe.address {
        IpAddr::V4(destination) => sent.get::<Ipv4>().is_some_and(|ipv4| {
            ipv4.destination == destination
                && ipv4.identification == nonzero_ipv4_identification(probe.sequence)
        }),
        IpAddr::V6(destination) => sent.get::<Ipv6>().is_some_and(|ipv6| {
            ipv6.destination == destination
                && ipv6.flow_label == (probe.sequence as u32) & 0x000f_ffff
        }),
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
        protocol::link::Ethernet,
        protocol::tunnel::Vxlan,
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

    fn inner_frame(ethernet: bool, payload: &[u8]) -> Bytes {
        let mut inner = Packet::new();
        if ethernet {
            inner.push(Ethernet {
                destination: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                source: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                ether_type: WireValue::Exact(0x0800),
            });
        }
        inner.push(Ipv4 {
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            ..Ipv4::default()
        });
        inner.push(Udp {
            source_port: 40_000,
            destination_port: 50_000,
            ..Udp::default()
        });
        inner.push(Raw::new(Bytes::copy_from_slice(payload)));
        build::Builder::new(builtin::registry())
            .build(inner, codec::Context::default(), build::Options::default())
            .unwrap()
            .bytes
    }

    fn vxlan_payload(vni: u32, inner: &[u8]) -> Bytes {
        let vni = vni.to_be_bytes();
        let mut payload = vec![0x08, 0, 0, 0, vni[1], vni[2], vni[3], 0];
        payload.extend_from_slice(inner);
        Bytes::from(payload)
    }

    fn geneve_payload(protocol_type: u16, vni: u32, inner: &[u8]) -> Bytes {
        let vni = vni.to_be_bytes();
        let mut payload = vec![
            0,
            0,
            (protocol_type >> 8) as u8,
            protocol_type as u8,
            vni[1],
            vni[2],
            vni[3],
            0,
        ];
        payload.extend_from_slice(inner);
        Bytes::from(payload)
    }

    #[test]
    fn vxlan_payloads_materialize_typed_tunnel_layers_and_round_trip_exactly() {
        let payload = vxlan_payload(0x12_34_56, &inner_frame(true, b"inner"));
        let probe = Probe {
            sequence: 9,
            attempt: 1,
            address: "192.0.2.10".parse().unwrap(),
            endpoint: ProbeEndpoint::Udp { port: 4789 },
            udp_payload: payload.clone(),
        };
        let mut packet = probe.packet();
        packet.get_mut::<Ipv4>().unwrap().source = "192.0.2.1".parse().unwrap();
        let built = build::Builder::new(builtin::registry())
            .build(packet, codec::Context::default(), build::Options::default())
            .unwrap();
        assert!(built.bytes.ends_with(&payload));
        assert_eq!(built.packet.get::<Vxlan>().unwrap().vni, 0x12_34_56);
        assert!(built.packet.get::<Ethernet>().is_some());
        assert!(sent_probe_matches(&probe, &built.packet));
        let mut changed = probe.clone();
        changed.udp_payload = vxlan_payload(0x12_34_56, &inner_frame(true, b"other"));
        assert!(!sent_probe_matches(&changed, &built.packet));
        let frame = Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap();
        let decoded = decode::Dissector::new(builtin::registry())
            .decode(frame, decode::Options::default())
            .unwrap();
        let destinations =
            packetcraftr_core::packet::semantics::live_destinations(&decoded.packet).unwrap();
        assert!(destinations.contains(&"192.0.2.10".parse().unwrap()));
        assert!(destinations.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn geneve_ipv4_payloads_materialize_typed_tunnel_layers_and_round_trip_exactly() {
        let payload = geneve_payload(0x0800, 77, &inner_frame(false, b"inner"));
        let probe = Probe {
            sequence: 11,
            attempt: 1,
            address: "2001:db8::10".parse().unwrap(),
            endpoint: ProbeEndpoint::Udp { port: 6081 },
            udp_payload: payload.clone(),
        };
        let mut packet = probe.packet();
        packet.get_mut::<Ipv6>().unwrap().source = "2001:db8::1".parse().unwrap();
        let built = build::Builder::new(builtin::registry())
            .build(packet, codec::Context::default(), build::Options::default())
            .unwrap();
        assert!(built.bytes.ends_with(&payload));
        assert_eq!(built.packet.get::<Geneve>().unwrap().vni, 77);
        assert!(built.packet.get::<Ipv4>().is_some());
        assert!(sent_probe_matches(&probe, &built.packet));
    }

    #[test]
    fn geneve_unknown_protocol_types_keep_the_exact_opaque_payload() {
        let payload = geneve_payload(0x88b5, 5, b"\xde\xad\xbe\xef");
        let probe = Probe {
            sequence: 3,
            attempt: 1,
            address: "192.0.2.10".parse().unwrap(),
            endpoint: ProbeEndpoint::Udp { port: 6081 },
            udp_payload: payload.clone(),
        };
        let mut packet = probe.packet();
        packet.get_mut::<Ipv4>().unwrap().source = "192.0.2.1".parse().unwrap();
        let built = build::Builder::new(builtin::registry())
            .build(packet, codec::Context::default(), build::Options::default())
            .unwrap();
        assert!(built.bytes.ends_with(&payload));
        assert!(built.packet.get::<Geneve>().is_some());
        assert_eq!(built.packet.get::<Raw>().unwrap().bytes, payload.slice(8..));
        assert!(sent_probe_matches(&probe, &built.packet));
    }

    #[test]
    fn registered_port_payload_that_is_not_the_registered_protocol_still_fails_strict_build() {
        let probe = Probe {
            sequence: 0,
            attempt: 1,
            address: "192.0.2.10".parse().unwrap(),
            endpoint: ProbeEndpoint::Udp { port: 4789 },
            udp_payload: Bytes::from_static(b"not a vxlan frame"),
        };
        let mut packet = probe.packet();
        packet.get_mut::<Ipv4>().unwrap().source = "192.0.2.1".parse().unwrap();
        assert!(
            build::Builder::new(builtin::registry())
                .build(packet, codec::Context::default(), build::Options::default())
                .is_err()
        );
        assert!(sent_probe_matches(&probe, &probe.packet()));
    }
}
