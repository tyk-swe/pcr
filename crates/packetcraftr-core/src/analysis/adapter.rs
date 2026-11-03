// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::BuiltinProtocol;
use std::net::IpAddr;

use crate::decode::DecodedPacket;
use crate::frame::checked_slice;
use crate::layer::Layer;
use crate::layer::Padding;
use crate::packet::Packet;
use crate::protocol::headers::{Ipv6ExtensionChain, is_walkable_ipv6_extension};
use crate::protocol::identity::{self, FragmentHeader, NetworkHeader, TcpHeader};
use crate::protocol::network::ip_protocol;
use crate::protocol::transport::Tcp;
use bytes::Bytes;

use crate::analysis::reassembly::ip::{
    Family as IpFamily, Fragment as ReassemblyFragment, Ipv4DatagramKey, Ipv4Fragment,
    Ipv6DatagramKey, Ipv6Fragment,
};
use crate::analysis::reassembly::tcp::{FlowKey, ScopedFlowKey, Segment};
use crate::analysis::scope::{EncapsulationIdentifier, Error as ScopeError, Interner, ScopeId};

pub(crate) struct IpFragments {
    pub(crate) atomic: Vec<IpFamily>,
    pub(crate) non_atomic: Option<ReassemblyFragment>,
}

/// Innermost transport of each kind.
pub(crate) struct Transports<'a> {
    pub(crate) tcp: Option<TcpTransport<'a>>,
    pub(crate) udp: Option<UdpTransport>,
    pub(crate) outermost: Option<usize>,
}

pub(crate) struct TcpTransport<'a> {
    pub(crate) index: usize,
    pub(crate) flow: FlowKey,
    pub(crate) header: TcpHeader<'a>,
    pub(crate) encapsulation: Vec<EncapsulationIdentifier>,
}

pub(crate) struct UdpTransport {
    pub(crate) index: usize,
    pub(crate) flow: FlowKey,
    pub(crate) encapsulation: Vec<EncapsulationIdentifier>,
}

fn ipv4_fragment(layer: &dyn Layer) -> Option<NetworkHeader> {
    match identity::network_header(layer) {
        Some(
            header @ NetworkHeader::V4 {
                fragment_offset,
                more_fragments,
                ..
            },
        ) if fragment_offset != 0 || more_fragments => Some(header),
        _ => None,
    }
}

fn ipv6_fragment(layer: &dyn Layer) -> Option<FragmentHeader> {
    identity::fragment_header(layer)
        .filter(|fragment| fragment.fragment_offset != 0 || fragment.more_fragments)
}

fn tunnel_identifier(
    layer: &dyn Layer,
    ethernet: Option<([u8; 6], [u8; 6])>,
) -> Option<EncapsulationIdentifier> {
    crate::protocol::identity::tunnel_identifier(layer, ethernet).map(|tunnel| match tunnel {
        crate::protocol::identity::TunnelId::Vlan { vlan_id } => {
            EncapsulationIdentifier::Vlan { vlan_id }
        }
        crate::protocol::identity::TunnelId::Vlan8021ad { vlan_id } => {
            EncapsulationIdentifier::Vlan8021ad { vlan_id }
        }
        crate::protocol::identity::TunnelId::Vxlan { vni } => {
            EncapsulationIdentifier::Vxlan { vni }
        }
        crate::protocol::identity::TunnelId::Geneve { vni } => {
            EncapsulationIdentifier::Geneve { vni }
        }
        crate::protocol::identity::TunnelId::Gre { key } => EncapsulationIdentifier::Gre { key },
        crate::protocol::identity::TunnelId::Mpls { label } => {
            EncapsulationIdentifier::Mpls { label }
        }
        crate::protocol::identity::TunnelId::Pppoe {
            session_id,
            endpoints,
        } => EncapsulationIdentifier::Pppoe {
            session_id,
            endpoints,
        },
        crate::protocol::identity::TunnelId::L2tpv3 { session_id } => {
            EncapsulationIdentifier::L2tpv3 { session_id }
        }
        crate::protocol::identity::TunnelId::Erspan { vlan, session_id } => {
            EncapsulationIdentifier::Erspan { vlan, session_id }
        }
        crate::protocol::identity::TunnelId::Ah { spi } => EncapsulationIdentifier::Ah { spi },
    })
}

struct IpHop {
    source: IpAddr,
    destination: IpAddr,
    path_index: usize,
}

/// The transport walk and the fragment walk build the encapsulation path
/// here; they must agree on it or the same conversation would land in two
/// scopes.
#[derive(Default)]
struct PathBuilder {
    path: Vec<EncapsulationIdentifier>,
    ethernet: Option<([u8; 6], [u8; 6])>,
}

impl PathBuilder {
    fn visit(&mut self, layer: &dyn Layer) -> Option<IpHop> {
        if let Some((source, destination)) = identity::link_addresses(layer) {
            self.ethernet = Some(ordered(source, destination));
        }
        let (source, destination) = if let Some(endpoints) = identity::network_endpoints(layer) {
            endpoints
        } else {
            if let Some(identifier) = tunnel_identifier(layer, self.ethernet) {
                self.path.push(identifier);
            }
            return None;
        };
        let (first, second) = ordered(source, destination);
        let path_index = self.path.len();
        self.path
            .push(EncapsulationIdentifier::Network { first, second });
        Some(IpHop {
            source,
            destination,
            path_index,
        })
    }

    fn without(&self, excluded: usize) -> Vec<EncapsulationIdentifier> {
        self.path
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != excluded)
            .map(|(_, identifier)| *identifier)
            .collect()
    }
}

pub(crate) fn transports(packet: &Packet) -> Transports<'_> {
    let mut network: Option<IpHop> = None;
    let mut path = PathBuilder::default();
    let mut found = Transports {
        tcp: None,
        udp: None,
        outermost: None,
    };
    for (index, layer) in packet.iter().enumerate() {
        if let Some(hop) = path.visit(layer) {
            network = Some(hop);
        } else if let Some(tcp) = identity::tcp_header(layer) {
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
                    header: tcp,
                    encapsulation: path.without(network.path_index),
                });
            }
        } else if let Some(udp) =
            identity::transport_key(layer).filter(|key| key.protocol == BuiltinProtocol::Udp)
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
                encapsulation: path.without(network.path_index),
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

pub(crate) type ScopeBase<'a> = Option<(&'a DecodedPacket, ScopeId)>;

pub(crate) fn ip_fragments(
    decoded: &DecodedPacket,
    base: ScopeBase<'_>,
    scopes: &mut Interner,
) -> Result<IpFragments, ScopeError> {
    struct Ipv6Network {
        source: std::net::Ipv6Addr,
        destination: std::net::Ipv6Addr,
        payload_length: crate::field::WireValue<u16>,
        layer_index: usize,
        path_index: usize,
    }

    let mut path = PathBuilder::default();
    let mut ipv6_network: Option<Ipv6Network> = None;
    let mut atomic = Vec::new();
    let mut non_atomic = None;

    for (index, layer) in decoded.packet.iter().enumerate() {
        if let Some(hop) = path.visit(layer) {
            if let Some(NetworkHeader::V6 {
                source,
                destination,
                payload_length,
                ..
            }) = identity::network_header(layer)
            {
                ipv6_network = Some(Ipv6Network {
                    source,
                    destination,
                    payload_length,
                    layer_index: index,
                    path_index: hop.path_index,
                });
                continue;
            }
            ipv6_network = None;
            let Some(NetworkHeader::V4 {
                source,
                destination,
                identification,
                fragment_offset,
                more_fragments,
                total_length,
                protocol,
                ..
            }) = ipv4_fragment(layer)
            else {
                continue;
            };
            let scope = scope_for(decoded, base, path.without(hop.path_index), scopes)?;
            let Some(layout) = decoded.layout.layer(index) else {
                continue;
            };
            let header = checked_slice(decoded.frame.bytes(), layout.range.start, layout.range.end)
                .unwrap_or_default();
            let total_length = total_length
                .exact()
                .copied()
                .map(usize::from)
                .unwrap_or_default();
            let header_length = layout.range.end.saturating_sub(layout.range.start);
            let payload_length = total_length.saturating_sub(header_length);
            let payload_end = layout.range.end.checked_add(payload_length);
            let payload = payload_end
                .and_then(|end| checked_slice(decoded.frame.bytes(), layout.range.end, end))
                .unwrap_or_default();
            let protocol = protocol.exact().copied().unwrap_or_default();
            non_atomic = Some(ReassemblyFragment::Ipv4(Ipv4Fragment {
                key: Ipv4DatagramKey {
                    scope,
                    source,
                    destination,
                    identification,
                    protocol,
                },
                fragment_offset,
                more_fragments,
                header,
                payload,
            }));
            break;
        }

        if BuiltinProtocol::Ipv6Fragment.identifies(layer) {
            let Some(fragment) = ipv6_fragment(layer) else {
                atomic.push(IpFamily::Ipv6);
                continue;
            };
            let Some(network) = &ipv6_network else {
                continue;
            };
            let scope = scope_for(decoded, base, path.without(network.path_index), scopes)?;
            let (Some(ipv6_layout), Some(fragment_layout)) = (
                decoded.layout.layer(network.layer_index),
                decoded.layout.layer(index),
            ) else {
                continue;
            };
            let prefix_start = ipv6_layout.range.start;
            let prefix = checked_slice(
                decoded.frame.bytes(),
                prefix_start,
                fragment_layout.range.start,
            )
            .unwrap_or_default();
            let predecessor_next_header_offset = index
                .checked_sub(1)
                .and_then(|previous| decoded.layout.layer(previous))
                .and_then(|layout| {
                    layout
                        .fields
                        .iter()
                        .find(|field| field.name(layout.schema) == Some("next_header"))
                })
                .and_then(|field| field.range.start.checked_sub(prefix_start))
                .unwrap_or(usize::MAX);
            let payload_length = network
                .payload_length
                .exact()
                .copied()
                .map(usize::from)
                .unwrap_or_default();
            let datagram_end = prefix_start
                .checked_add(40)
                .and_then(|base| base.checked_add(payload_length));
            let payload = datagram_end
                .and_then(|end| {
                    checked_slice(decoded.frame.bytes(), fragment_layout.range.end, end)
                })
                .unwrap_or_default();
            non_atomic = Some(ReassemblyFragment::Ipv6(Ipv6Fragment {
                key: Ipv6DatagramKey {
                    scope,
                    source: network.source,
                    destination: network.destination,
                    identification: fragment.identification,
                },
                fragment_offset: fragment.fragment_offset,
                more_fragments: fragment.more_fragments,
                next_header: fragment.next_header.exact().copied().unwrap_or_default(),
                unfragmentable_prefix: prefix,
                predecessor_next_header_offset,
                payload,
            }));
            break;
        }
    }

    Ok(IpFragments { atomic, non_atomic })
}

/// Excludes padding identified at or above TCP (such as link padding), but
/// retains bytes a protocol inside the payload treated as padding.
pub(crate) fn transport_payload(decoded: &DecodedPacket, transport_index: usize) -> Bytes {
    let Some(tcp_layout) = decoded.layout.layer(transport_index) else {
        return Bytes::new();
    };
    let start = tcp_layout.range.end;
    let mut end = start;
    for (index, layer) in decoded
        .packet
        .iter()
        .enumerate()
        .skip(transport_index.saturating_add(1))
    {
        if let Some(padding) = Padding::from_layer(layer)
            && padding.excluded_from(transport_index)
        {
            continue;
        }
        if let Some(layout) = decoded.layout.layer(index) {
            end = end.max(layout.range.end);
        }
    }
    let start = start.min(decoded.frame.bytes().len());
    let end = end.min(decoded.frame.bytes().len());
    if end > start {
        checked_slice(decoded.frame.bytes(), start, end).unwrap_or_default()
    } else {
        Bytes::new()
    }
}

pub(crate) fn tcp_segment(
    decoded: &DecodedPacket,
    transport: TcpTransport<'_>,
    base: ScopeBase<'_>,
    scopes: &mut Interner,
) -> Result<Option<Segment>, ScopeError> {
    if transport_hidden_by_fragment(decoded, transport.index, ip_protocol::TCP) {
        return Ok(None);
    }
    let scope = scope_for(decoded, base, transport.encapsulation, scopes)?;
    Ok(Some(Segment {
        flow: ScopedFlowKey {
            scope,
            flow: transport.flow,
        },
        sequence: transport.header.sequence,
        payload: transport_payload(decoded, transport.index),
        syn: transport.header.flags & Tcp::SYN != 0,
        fin: transport.header.flags & Tcp::FIN != 0,
        rst: transport.header.flags & Tcp::RST != 0,
    }))
}

pub(crate) fn udp_flow(
    decoded: &DecodedPacket,
    transport: UdpTransport,
    base: ScopeBase<'_>,
    scopes: &mut Interner,
) -> Result<Option<ScopedFlowKey>, ScopeError> {
    if transport_hidden_by_fragment(decoded, transport.index, ip_protocol::UDP) {
        return Ok(None);
    }
    let scope = scope_for(decoded, base, transport.encapsulation, scopes)?;
    Ok(Some(ScopedFlowKey {
        scope,
        flow: transport.flow,
    }))
}

fn scope_for(
    decoded: &DecodedPacket,
    base: ScopeBase<'_>,
    encapsulation: Vec<EncapsulationIdentifier>,
    scopes: &mut Interner,
) -> Result<ScopeId, ScopeError> {
    match base {
        Some((physical, base_scope)) => {
            let replayed = replayed_ipv6_encapsulation(physical);
            scopes.replace_suffix(base_scope, &replayed, &encapsulation)
        }
        None => scopes.intern(decoded.frame.interface, encapsulation),
    }
}

fn transport_hidden_by_fragment(
    decoded: &DecodedPacket,
    transport_index: usize,
    protocol: u8,
) -> bool {
    decoded.packet.iter().enumerate().any(|(index, layer)| {
        if index <= transport_index {
            return false;
        }
        if BuiltinProtocol::Ipv4.identifies(layer) {
            return ipv4_fragment(layer).is_some_and(|header| {
                let NetworkHeader::V4 {
                    protocol: inner, ..
                } = header
                else {
                    return false;
                };
                inner.exact().copied() == Some(protocol)
            });
        }
        ipv6_fragment(layer).is_some_and(|fragment| {
            ipv6_fragment_transport_protocol(decoded, index, &fragment) == Some(protocol)
        })
    })
}

fn ipv6_fragment_transport_protocol(
    decoded: &DecodedPacket,
    fragment_index: usize,
    fragment: &FragmentHeader,
) -> Option<u8> {
    let next_header = fragment.next_header.exact().copied()?;
    // A nonzero fragment starts in the middle of the fragmentable part, so
    // the extension chain cannot be resolved from this frame.
    if fragment.fragment_offset != 0 && is_walkable_ipv6_extension(next_header) {
        return None;
    }
    let (ipv6_index, payload_length) = decoded
        .packet
        .iter()
        .take(fragment_index)
        .enumerate()
        .rev()
        .find_map(|(index, layer)| match identity::network_header(layer) {
            Some(NetworkHeader::V6 { payload_length, .. }) => Some((index, payload_length)),
            _ => None,
        })?;
    let ipv6_layout = decoded.layout.layer(ipv6_index)?;
    let payload_length = usize::from(payload_length.exact().copied()?);
    let payload_end = ipv6_layout.range.end.checked_add(payload_length)?;
    let payload = decoded
        .layout
        .layer(fragment_index)
        .and_then(|layout| decoded.frame.bytes().get(layout.range.end..payload_end))?;
    // A further Fragment header ends the walk: its protocol is the answer,
    // because the bytes behind it may belong to another fragment.
    let mut chain =
        Ipv6ExtensionChain::new(payload, 0, next_header).with_ceiling(payload.len() / 8);
    loop {
        let (protocol, _) = chain.position();
        if protocol == ip_protocol::FRAGMENT {
            return Some(protocol);
        }
        match chain.next() {
            None => return Some(protocol),
            Some(Ok(_)) => {}
            Some(Err(_)) => return None,
        }
    }
}

fn replayed_ipv6_encapsulation(decoded: &DecodedPacket) -> Vec<EncapsulationIdentifier> {
    let mut in_ipv6 = false;
    let mut replayed = Vec::new();
    for layer in decoded.packet.iter() {
        if BuiltinProtocol::Ipv4.identifies(layer) {
            in_ipv6 = false;
            replayed.clear();
        } else if BuiltinProtocol::Ipv6.identifies(layer) {
            in_ipv6 = true;
            replayed.clear();
        } else if BuiltinProtocol::Ipv6Fragment.identifies(layer) {
            if in_ipv6 && ipv6_fragment(layer).is_some() {
                return replayed;
            }
        } else if in_ipv6
            && let Some(identity::TunnelId::Ah { spi }) = identity::tunnel_identifier(layer, None)
        {
            replayed.push(EncapsulationIdentifier::Ah { spi });
        }
    }
    Vec::new()
}

pub(crate) fn replayed_ip_prefix_layers(decoded: &DecodedPacket) -> usize {
    let mut ipv6_start = None;
    for (index, layer) in decoded.packet.iter().enumerate() {
        if BuiltinProtocol::Ipv4.identifies(layer) {
            ipv6_start = None;
            if ipv4_fragment(layer).is_some() {
                return 1;
            }
        } else if BuiltinProtocol::Ipv6.identifies(layer) {
            ipv6_start = Some(index);
        } else if ipv6_fragment(layer).is_some()
            && let Some(start) = ipv6_start
        {
            return index.saturating_sub(start);
        }
    }
    0
}
