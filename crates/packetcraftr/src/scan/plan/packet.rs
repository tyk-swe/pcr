// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::codec::{self, DecodedLayer, LayerDecodeContext};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::application::ntp::Ntp;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::tunnel::Geneve;
use packetcraftr_core::protocol::{
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::{Tcp, Udp},
};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{build, decode, packet::Packet, protocol::BuiltinProtocol};

use crate::correlation::{
    EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port, icmp_identity, nonzero_ipv4_identification,
};

use super::Probe;
use crate::probe::ProbeEndpoint;

fn scan_udp_source_port(attempt: u32) -> u16 {
    ephemeral_source_port(
        EPHEMERAL_SOURCE_PORT_BASE,
        u64::from(attempt.saturating_sub(1)),
    )
}

// the operation-local sequence is reduced to the 32-bit and 20-bit wire fields the probe carries;
// sent_probe_matches applies the same reduction when comparing, so even a wrapped counter still
// matches
pub(in crate::scan) fn probe_packet(probe: &Probe) -> Packet {
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
            if let Some(profile) = &probe.udp_profile {
                if profile.raw_payload() {
                    if !probe.udp_payload.is_empty() {
                        packet.push(Raw::new(probe.udp_payload.clone()));
                    }
                } else {
                    if let Ok(dns) = Dns::try_from(probe.udp_payload.clone()) {
                        packet.push(dns);
                    } else {
                        packet.push(Raw::new(probe.udp_payload.clone()));
                    }
                }
            } else {
                push_udp_payload(&mut packet, port, &probe.udp_payload);
            }
            &mut packet
        }
        ProbeEndpoint::Icmp => match probe.address {
            IpAddr::V4(_) => packet.push(Icmpv4 {
                body: icmp_identity(ICMP_IDENTITY_TAG, probe.sequence),
                ..Icmpv4::default()
            }),
            IpAddr::V6(_) => packet.push(Icmpv6 {
                body: icmp_identity(ICMP_IDENTITY_TAG, probe.sequence),
                ..Icmpv6::default()
            }),
        },
    };
    packet
}

/// Second byte of every scan ICMP echo payload; see [`icmp_identity`].
const ICMP_IDENTITY_TAG: u8 = 0x43;

const DNS_PORT: u16 = 53;
const NTP_PORT: u16 = 123;
const VXLAN_PORT: u16 = 4789;
const GENEVE_PORT: u16 = 6081;
const GENEVE_ETHERNET: u16 = 0x6558;
const GENEVE_IPV4: u16 = 0x0800;
const GENEVE_IPV6: u16 = 0x86dd;

// Materialize recognized payloads under their registered UDP ports so strict
// construction retains the same application bytes and protocol identity.
fn push_udp_payload(packet: &mut Packet, port: u16, payload: &Bytes) {
    if payload.is_empty() {
        return;
    }
    let registry = builtin::registry();
    if port == DNS_PORT
        && let Ok(dns) = Dns::try_from(payload.clone())
    {
        packet.push(dns);
        return;
    }
    if matches!(port, 67 | 68)
        && let Ok(dhcp) =
            packetcraftr_core::protocol::application::dhcp::Dhcpv4::try_from(payload.clone())
    {
        packet.push(dhcp);
        return;
    }
    if matches!(port, 546 | 547)
        && let Ok(dhcp) =
            packetcraftr_core::protocol::application::dhcp::Dhcpv6::try_from(payload.clone())
    {
        packet.push(dhcp);
        return;
    }
    if port == NTP_PORT
        && let Some(ntp) = decode_layer(&registry, BuiltinProtocol::Ntp.as_str(), payload)
        && ntp.layer.is::<Ntp>()
        && ntp.consumed == payload.len()
    {
        packet.push_boxed(ntp.layer);
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

fn decode_layer(registry: &Registry, protocol: &str, payload: &[u8]) -> Option<DecodedLayer> {
    registry
        .codec(protocol)?
        .decode(
            Bytes::copy_from_slice(payload),
            &LayerDecodeContext {
                parent: None,
                registry,
                network: None,
                hop_limit: None,
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
        .map(packetcraftr_core::layer::Layer::clone_box)
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
    let Some(header) = decode_layer(registry, protocol, payload) else {
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
    let Some(header) = decode_layer(registry, "geneve", payload) else {
        return false;
    };
    let Some(geneve) = header.layer.downcast_ref::<Geneve>() else {
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

pub(in crate::scan) fn sent_probe_matches(probe: &Probe, sent: &Packet) -> bool {
    if probe.udp_profile.as_ref().is_some_and(|profile| {
        probe.endpoint.transport() != crate::probe::Transport::Udp
            || profile.payload(probe.sequence) != probe.udp_payload
    }) {
        return false;
    }
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
                icmp.icmp_type == 8
                    && icmp.code == 0
                    && icmp.body == icmp_identity(ICMP_IDENTITY_TAG, probe.sequence)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128
                    && icmp.code == 0
                    && icmp.body == icmp_identity(ICMP_IDENTITY_TAG, probe.sequence)
            }),
        },
    }
}
