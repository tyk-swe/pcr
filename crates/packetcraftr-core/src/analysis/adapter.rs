// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-specific decoded-layer inspection and reassembly input adapters.

use std::net::IpAddr;

use crate::Packet;
use crate::decode::DecodedPacket;
use crate::layer::Padding;
use crate::protocol::link::{Vlan, Vlan8021ad};
use crate::protocol::network::{Ipv4, Ipv6};
use crate::protocol::transport::{Tcp, Udp};
use crate::protocol::tunnel::gre::Gre;
use crate::protocol::tunnel::{Ah, Erspan, Geneve, L2tpv3, Mpls, Pppoe, Vxlan};
use bytes::Bytes;

use crate::analysis::reassembly::tcp::{FlowKey, ScopedFlowKey, Segment};
use crate::analysis::scope::{EncapsulationIdentifier, Interner};

/// The innermost transport of each kind in a decoded stack.
///
/// The innermost occurrence is the one an operator means: in a tunnelled
/// stack the outer encapsulation carries the inner conversation, and the
/// inner endpoints are the conversation's endpoints. The kinds are tracked
/// separately because an encapsulated frame legitimately belongs to both a
/// UDP conversation (the tunnel) and a TCP conversation (the payload).
pub(crate) struct Transports<'a> {
    pub(crate) tcp: Option<TcpTransport<'a>>,
    pub(crate) udp: Option<UdpTransport>,
    /// Index of the outermost transport layer of either kind. In a
    /// same-transport tunnel this differs from the retained innermost
    /// occurrence, marking headers whose conversation carries no index.
    pub(crate) outermost: Option<usize>,
}

pub(crate) struct TcpTransport<'a> {
    pub(crate) index: usize,
    pub(crate) flow: FlowKey,
    pub(crate) layer: &'a Tcp,
    pub(crate) encapsulation: Vec<EncapsulationIdentifier>,
}

pub(crate) struct UdpTransport {
    pub(crate) index: usize,
    pub(crate) flow: FlowKey,
    pub(crate) encapsulation: Vec<EncapsulationIdentifier>,
}

pub(crate) fn transports(packet: &Packet) -> Transports<'_> {
    struct Network {
        source: IpAddr,
        destination: IpAddr,
        path_index: usize,
    }

    let mut network: Option<Network> = None;
    let mut path = Vec::new();
    let mut found = Transports {
        tcp: None,
        udp: None,
        outermost: None,
    };
    for (index, layer) in packet.iter().enumerate() {
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let source = IpAddr::V4(ipv4.source);
            let destination = IpAddr::V4(ipv4.destination);
            let (first, second) = ordered(source, destination);
            path.push(EncapsulationIdentifier::Network { first, second });
            network = Some(Network {
                source,
                destination,
                path_index: path.len() - 1,
            });
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let source = IpAddr::V6(ipv6.source);
            let destination = IpAddr::V6(ipv6.destination);
            let (first, second) = ordered(source, destination);
            path.push(EncapsulationIdentifier::Network { first, second });
            network = Some(Network {
                source,
                destination,
                path_index: path.len() - 1,
            });
        } else if let Some(vlan) = layer.as_any().downcast_ref::<Vlan>() {
            path.push(EncapsulationIdentifier::Vlan {
                vlan_id: vlan.vlan_id,
            });
        } else if let Some(vlan) = layer.as_any().downcast_ref::<Vlan8021ad>() {
            path.push(EncapsulationIdentifier::Vlan8021ad {
                vlan_id: vlan.vlan_id,
            });
        } else if let Some(vxlan) = layer.as_any().downcast_ref::<Vxlan>() {
            path.push(EncapsulationIdentifier::Vxlan { vni: vxlan.vni });
        } else if let Some(geneve) = layer.as_any().downcast_ref::<Geneve>() {
            path.push(EncapsulationIdentifier::Geneve { vni: geneve.vni });
        } else if let Some(gre) = layer.as_any().downcast_ref::<Gre>() {
            path.push(EncapsulationIdentifier::Gre { key: gre.key });
        } else if let Some(mpls) = layer.as_any().downcast_ref::<Mpls>() {
            path.push(EncapsulationIdentifier::Mpls { label: mpls.label });
        } else if let Some(pppoe) = layer.as_any().downcast_ref::<Pppoe>() {
            path.push(EncapsulationIdentifier::Pppoe {
                session_id: pppoe.session_id,
            });
        } else if let Some(l2tp) = layer.as_any().downcast_ref::<L2tpv3>() {
            path.push(EncapsulationIdentifier::L2tpv3 {
                session_id: l2tp.session_id,
            });
        } else if let Some(erspan) = layer.as_any().downcast_ref::<Erspan>() {
            path.push(EncapsulationIdentifier::Erspan {
                vlan: erspan.vlan,
                session_id: erspan.session_id,
            });
        } else if let Some(ah) = layer.as_any().downcast_ref::<Ah>() {
            path.push(EncapsulationIdentifier::Ah { spi: ah.spi });
        } else if let Some(tcp) = layer.as_any().downcast_ref::<Tcp>() {
            if let Some(network) = &network {
                found.outermost.get_or_insert(index);
                let flow = FlowKey {
                    source: network.source,
                    source_port: tcp.source_port,
                    destination: network.destination,
                    destination_port: tcp.destination_port,
                };
                found.tcp = Some(TcpTransport {
                    index,
                    flow,
                    layer: tcp,
                    encapsulation: path_without(&path, network.path_index),
                });
            }
        } else if let Some(udp) = layer.as_any().downcast_ref::<Udp>()
            && let Some(network) = &network
        {
            found.outermost.get_or_insert(index);
            let flow = FlowKey {
                source: network.source,
                source_port: udp.source_port,
                destination: network.destination,
                destination_port: udp.destination_port,
            };
            found.udp = Some(UdpTransport {
                index,
                flow,
                encapsulation: path_without(&path, network.path_index),
            });
        }
    }
    found
}

fn ordered<T: Ord>(first: T, second: T) -> (T, T) {
    if first <= second {
        (first, second)
    } else {
        (second, first)
    }
}

fn path_without(path: &[EncapsulationIdentifier], excluded: usize) -> Vec<EncapsulationIdentifier> {
    path.iter()
        .enumerate()
        .filter(|(index, _)| *index != excluded)
        .map(|(_, identifier)| identifier.clone())
        .collect()
}

/// The exact wire bytes of the TCP payload at `transport_index`.
///
/// The payload is reconstructed from the decode layout rather than from a
/// trailing raw layer, so it stays exact when a registry decodes the payload
/// into typed layers. Padding that a layer at or above the TCP layer already
/// excluded — link padding beyond the IP total length — is not stream data
/// and is left out; padding first excluded by a layer inside the payload is
/// stream data the inner protocol merely declined, and stays in.
pub(crate) fn transport_payload(decoded: &DecodedPacket, transport_index: usize) -> Bytes {
    let Some(tcp_layout) = decoded.layout.layer(transport_index) else {
        return Bytes::new();
    };
    let start = tcp_layout.range.end;
    let mut end = start;
    for (index, layer) in decoded.packet.iter().enumerate().skip(transport_index + 1) {
        if let Some(padding) = layer.as_any().downcast_ref::<Padding>()
            && padding
                .outside_layer
                .is_none_or(|outside| outside <= transport_index)
        {
            continue;
        }
        if let Some(layout) = decoded.layout.layer(index) {
            end = end.max(layout.range.end);
        }
    }
    let start = start.min(decoded.original.len());
    let end = end.min(decoded.original.len());
    if end > start {
        decoded.original.slice(start..end)
    } else {
        Bytes::new()
    }
}

/// Maps a decoded stack onto the innermost TCP segment, when there is one.
///
/// A pure control segment has an empty payload rather than no segment,
/// because an empty SYN, FIN, or RST still carries stream state.
pub(crate) fn tcp_segment(
    decoded: &DecodedPacket,
    scopes: &mut Interner,
) -> Result<Option<Segment>, crate::analysis::scope::Error> {
    let Some(transport) = transports(&decoded.packet).tcp else {
        return Ok(None);
    };
    let scope = scopes.intern(decoded.frame.interface, transport.encapsulation)?;
    Ok(Some(Segment {
        flow: ScopedFlowKey {
            scope,
            flow: transport.flow,
        },
        sequence: transport.layer.sequence,
        payload: transport_payload(decoded, transport.index),
        syn: transport.layer.flags & Tcp::SYN != 0,
        fin: transport.layer.flags & Tcp::FIN != 0,
        rst: transport.layer.flags & Tcp::RST != 0,
    }))
}

/// Maps a decoded stack onto the innermost UDP flow, when there is one.
pub(crate) fn udp_flow(
    decoded: &DecodedPacket,
    scopes: &mut Interner,
) -> Result<Option<ScopedFlowKey>, crate::analysis::scope::Error> {
    let Some(transport) = transports(&decoded.packet).udp else {
        return Ok(None);
    };
    let scope = scopes.intern(decoded.frame.interface, transport.encapsulation)?;
    Ok(Some(ScopedFlowKey {
        scope,
        flow: transport.flow,
    }))
}
