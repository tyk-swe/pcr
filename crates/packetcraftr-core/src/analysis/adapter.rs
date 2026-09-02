// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-specific decoded-layer inspection and reassembly input adapters.

use std::net::IpAddr;

use crate::Packet;
use crate::byte_slice::checked_slice;
use crate::decode::DecodedPacket;
use crate::layer::Layer;
use crate::layer::Padding;
use crate::protocol::gre::Gre;
use crate::protocol::ipv6::Fragment as Ipv6FragmentHeader;
use crate::protocol::link::{Vlan, Vlan8021ad};
use crate::protocol::network::{
    Ipv4, Ipv6, ipv6_extension_header_length, is_walkable_ipv6_extension,
};
use crate::protocol::transport::{Tcp, Udp};
use crate::protocol::tunnel::{Ah, Erspan, Geneve, L2tpv3, Mpls, Pppoe, Vxlan};
use bytes::Bytes;

use crate::analysis::reassembly::ip::{
    Family as IpFamily, Fragment as ReassemblyFragment, Ipv4DatagramKey, Ipv4Fragment,
    Ipv6DatagramKey, Ipv6Fragment,
};
use crate::analysis::reassembly::tcp::{FlowKey, ScopedFlowKey, Segment};
use crate::analysis::scope::{EncapsulationIdentifier, Error as ScopeError, Interner, ScopeId};

/// Fragment observations extracted from one physical decoded frame.
///
/// A non-atomic outer fragment makes the rest of its payload opaque, so at
/// most one non-atomic fragment can occur. Atomic IPv6 Fragment headers are
/// transparent to dissection and may precede an inner non-atomic fragment.
pub(crate) struct IpFragments {
    pub(crate) atomic: Vec<IpFamily>,
    pub(crate) non_atomic: Option<ReassemblyFragment>,
}

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

/// The IPv4 header at this layer, when it is a fragment reassembly must see.
///
/// Offset zero with no More Fragments is an *atomic* fragment: a complete
/// datagram that is not reassembly input and whose payload stays transparent
/// to dissection. Every walk that looks for fragments needs both the
/// downcast and that test, so they travel together here rather than being
/// restated at each site.
fn ipv4_fragment(layer: &dyn Layer) -> Option<&Ipv4> {
    layer
        .as_any()
        .downcast_ref::<Ipv4>()
        .filter(|ipv4| ipv4.fragment_offset != 0 || ipv4.more_fragments)
}

/// The IPv6 Fragment header at this layer, when it is non-atomic. The atomic
/// rule is the same one [`ipv4_fragment`] documents.
fn ipv6_fragment(layer: &dyn Layer) -> Option<&Ipv6FragmentHeader> {
    layer
        .as_any()
        .downcast_ref::<Ipv6FragmentHeader>()
        .filter(|fragment| fragment.fragment_offset != 0 || fragment.more_fragments)
}

/// Scope identity contributed by one tunnel or tag layer.
///
/// The transport walk and the fragment walk must agree on the encapsulation
/// path or the same conversation would land in two scopes, so both read this
/// single table rather than repeating the downcast chain.
fn tunnel_identifier(layer: &dyn Layer) -> Option<EncapsulationIdentifier> {
    let any = layer.as_any();
    if let Some(vlan) = any.downcast_ref::<Vlan>() {
        Some(EncapsulationIdentifier::Vlan {
            vlan_id: vlan.vlan_id,
        })
    } else if let Some(vlan) = any.downcast_ref::<Vlan8021ad>() {
        Some(EncapsulationIdentifier::Vlan8021ad {
            vlan_id: vlan.vlan_id,
        })
    } else if let Some(vxlan) = any.downcast_ref::<Vxlan>() {
        Some(EncapsulationIdentifier::Vxlan { vni: vxlan.vni })
    } else if let Some(geneve) = any.downcast_ref::<Geneve>() {
        Some(EncapsulationIdentifier::Geneve { vni: geneve.vni })
    } else if let Some(gre) = any.downcast_ref::<Gre>() {
        Some(EncapsulationIdentifier::Gre { key: gre.key })
    } else if let Some(mpls) = any.downcast_ref::<Mpls>() {
        Some(EncapsulationIdentifier::Mpls { label: mpls.label })
    } else if let Some(pppoe) = any.downcast_ref::<Pppoe>() {
        Some(EncapsulationIdentifier::Pppoe {
            session_id: pppoe.session_id,
        })
    } else if let Some(l2tp) = any.downcast_ref::<L2tpv3>() {
        Some(EncapsulationIdentifier::L2tpv3 {
            session_id: l2tp.session_id,
        })
    } else if let Some(erspan) = any.downcast_ref::<Erspan>() {
        Some(EncapsulationIdentifier::Erspan {
            vlan: erspan.vlan,
            session_id: erspan.session_id,
        })
    } else {
        any.downcast_ref::<Ah>()
            .map(|ah| EncapsulationIdentifier::Ah { spi: ah.spi })
    }
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
            let path_index = path.len();
            path.push(EncapsulationIdentifier::Network { first, second });
            network = Some(Network {
                source,
                destination,
                path_index,
            });
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let source = IpAddr::V6(ipv6.source);
            let destination = IpAddr::V6(ipv6.destination);
            let (first, second) = ordered(source, destination);
            let path_index = path.len();
            path.push(EncapsulationIdentifier::Network { first, second });
            network = Some(Network {
                source,
                destination,
                path_index,
            });
        } else if let Some(identifier) = tunnel_identifier(layer) {
            path.push(identifier);
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
        .map(|(_, identifier)| *identifier)
        .collect()
}

/// Extracts the exact fragment payload and reconstruction metadata from one
/// physical frame. Scope interning uses the same path vocabulary as transport
/// indexing, excluding the fragmented network header whose endpoints already
/// live in the datagram key.
pub(crate) fn ip_fragments(
    decoded: &DecodedPacket,
    scopes: &mut Interner,
) -> Result<IpFragments, ScopeError> {
    ip_fragments_with_scope(decoded, None, &[], scopes)
}

/// Extracts fragments from a derived datagram while preserving the parent
/// datagram's already-interned capture scope.
pub(crate) fn ip_fragments_in_scope(
    decoded: &DecodedPacket,
    source: &DecodedPacket,
    base_scope: ScopeId,
    scopes: &mut Interner,
) -> Result<IpFragments, ScopeError> {
    let replayed = replayed_ipv6_encapsulation(source);
    ip_fragments_with_scope(decoded, Some(base_scope), &replayed, scopes)
}

/// Base for scope interning: [`None`] for a physical frame, or the fragment
/// source and already-interned base scope for a derived datagram view.
pub(crate) type ScopeBase<'a> = Option<(&'a DecodedPacket, ScopeId)>;

fn ip_fragments_with_scope(
    decoded: &DecodedPacket,
    base_scope: Option<ScopeId>,
    replayed: &[EncapsulationIdentifier],
    scopes: &mut Interner,
) -> Result<IpFragments, ScopeError> {
    struct Ipv6Network<'a> {
        layer: &'a Ipv6,
        layer_index: usize,
        path_index: usize,
    }

    let mut path = Vec::new();
    let mut ipv6_network: Option<Ipv6Network<'_>> = None;
    let mut atomic = Vec::new();
    let mut non_atomic = None;

    for (index, layer) in decoded.packet.iter().enumerate() {
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let source = IpAddr::V4(ipv4.source);
            let destination = IpAddr::V4(ipv4.destination);
            let (first, second) = ordered(source, destination);
            let path_index = path.len();
            path.push(EncapsulationIdentifier::Network { first, second });
            ipv6_network = None;
            let Some(ipv4) = ipv4_fragment(layer) else {
                continue;
            };
            let scope = fragment_scope(
                decoded,
                base_scope,
                replayed,
                path_without(&path, path_index),
                scopes,
            )?;
            let Some(layout) = decoded.layout.layer(index) else {
                continue;
            };
            let header = checked_slice(&decoded.original, layout.range.start, layout.range.end)
                .unwrap_or_default();
            let total_length = ipv4
                .total_length
                .exact()
                .copied()
                .map(usize::from)
                .unwrap_or_default();
            let header_length = layout.range.end.saturating_sub(layout.range.start);
            let payload_length = total_length.saturating_sub(header_length);
            let payload_end = layout.range.end.checked_add(payload_length);
            let payload = payload_end
                .and_then(|end| checked_slice(&decoded.original, layout.range.end, end))
                .unwrap_or_default();
            let protocol = ipv4.protocol.exact().copied().unwrap_or_default();
            non_atomic = Some(ReassemblyFragment::Ipv4(Ipv4Fragment {
                key: Ipv4DatagramKey {
                    scope,
                    source: ipv4.source,
                    destination: ipv4.destination,
                    identification: ipv4.identification,
                    protocol,
                },
                fragment_offset: ipv4.fragment_offset,
                more_fragments: ipv4.more_fragments,
                header,
                payload,
            }));
            break;
        }

        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let source = IpAddr::V6(ipv6.source);
            let destination = IpAddr::V6(ipv6.destination);
            let (first, second) = ordered(source, destination);
            let path_index = path.len();
            path.push(EncapsulationIdentifier::Network { first, second });
            ipv6_network = Some(Ipv6Network {
                layer: ipv6,
                layer_index: index,
                path_index,
            });
            continue;
        }

        if layer.as_any().is::<Ipv6FragmentHeader>() {
            let Some(fragment) = ipv6_fragment(layer) else {
                atomic.push(IpFamily::Ipv6);
                continue;
            };
            let Some(network) = &ipv6_network else {
                continue;
            };
            let scope = fragment_scope(
                decoded,
                base_scope,
                replayed,
                path_without(&path, network.path_index),
                scopes,
            )?;
            let (Some(ipv6_layout), Some(fragment_layout)) = (
                decoded.layout.layer(network.layer_index),
                decoded.layout.layer(index),
            ) else {
                continue;
            };
            let prefix_start = ipv6_layout.range.start;
            let prefix =
                checked_slice(&decoded.original, prefix_start, fragment_layout.range.start)
                    .unwrap_or_default();
            let predecessor_next_header_offset = index
                .checked_sub(1)
                .and_then(|previous| decoded.layout.layer(previous))
                .and_then(|layout| {
                    layout
                        .fields
                        .iter()
                        .find(|field| field.name == "next_header")
                })
                .and_then(|field| field.range.start.checked_sub(prefix_start))
                .unwrap_or(usize::MAX);
            let payload_length = network
                .layer
                .payload_length
                .exact()
                .copied()
                .map(usize::from)
                .unwrap_or_default();
            let datagram_end = prefix_start
                .checked_add(40)
                .and_then(|base| base.checked_add(payload_length));
            let payload = datagram_end
                .and_then(|end| checked_slice(&decoded.original, fragment_layout.range.end, end))
                .unwrap_or_default();
            non_atomic = Some(ReassemblyFragment::Ipv6(Ipv6Fragment {
                key: Ipv6DatagramKey {
                    scope,
                    source: network.layer.source,
                    destination: network.layer.destination,
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

        if let Some(identifier) = tunnel_identifier(layer) {
            path.push(identifier);
        }
    }

    Ok(IpFragments { atomic, non_atomic })
}

fn fragment_scope(
    decoded: &DecodedPacket,
    base_scope: Option<ScopeId>,
    replayed: &[EncapsulationIdentifier],
    encapsulation: Vec<EncapsulationIdentifier>,
    scopes: &mut Interner,
) -> Result<ScopeId, ScopeError> {
    match base_scope {
        Some(base_scope) => scopes.replace_suffix(base_scope, replayed, &encapsulation),
        None => scopes.intern(decoded.frame.interface, encapsulation),
    }
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
    for (index, layer) in decoded
        .packet
        .iter()
        .enumerate()
        .skip(transport_index.saturating_add(1))
    {
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
        checked_slice(&decoded.original, start, end).unwrap_or_default()
    } else {
        Bytes::new()
    }
}

/// Maps an already-located TCP transport onto a reassembly segment.
///
/// A pure control segment has an empty payload rather than no segment,
/// because an empty SYN, FIN, or RST still carries stream state. [`None`]
/// means the transport is the visible carrier of a fragmented same-transport
/// child, which the eventual completion will index instead. A derived
/// datagram view passes its fragment source and base scope in `base` to
/// preserve the physical fragments' already-interned capture scope.
pub(crate) fn tcp_segment(
    decoded: &DecodedPacket,
    transport: TcpTransport<'_>,
    base: ScopeBase<'_>,
    scopes: &mut Interner,
) -> Result<Option<Segment>, ScopeError> {
    if transport_hidden_by_fragment(decoded, transport.index, 6) {
        return Ok(None);
    }
    let scope = transport_scope(decoded, base, transport.encapsulation, scopes)?;
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

/// Maps an already-located UDP transport onto its scoped flow. `base` and
/// the [`None`] outcome follow the same convention as [`tcp_segment`].
pub(crate) fn udp_flow(
    decoded: &DecodedPacket,
    transport: UdpTransport,
    base: ScopeBase<'_>,
    scopes: &mut Interner,
) -> Result<Option<ScopedFlowKey>, ScopeError> {
    if transport_hidden_by_fragment(decoded, transport.index, 17) {
        return Ok(None);
    }
    let scope = transport_scope(decoded, base, transport.encapsulation, scopes)?;
    Ok(Some(ScopedFlowKey {
        scope,
        flow: transport.flow,
    }))
}

fn transport_scope(
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

/// A directly declared same-kind transport below an opaque fragment is the
/// eventual innermost conversation. Do not allocate an index to its visible
/// carrier merely because fragmentation has temporarily hidden the child.
fn transport_hidden_by_fragment(
    decoded: &DecodedPacket,
    transport_index: usize,
    protocol: u8,
) -> bool {
    decoded.packet.iter().enumerate().any(|(index, layer)| {
        if index <= transport_index {
            return false;
        }
        if layer.as_any().is::<Ipv4>() {
            return ipv4_fragment(layer)
                .is_some_and(|ipv4| ipv4.protocol.exact().copied() == Some(protocol));
        }
        ipv6_fragment(layer).is_some_and(|fragment| {
            ipv6_fragment_transport_protocol(decoded, index, fragment) == Some(protocol)
        })
    })
}

fn ipv6_fragment_transport_protocol(
    decoded: &DecodedPacket,
    fragment_index: usize,
    fragment: &Ipv6FragmentHeader,
) -> Option<u8> {
    let mut next_header = fragment.next_header.exact().copied()?;
    // A nonzero fragment starts in the middle of the fragmentable part, so
    // the extension chain cannot be resolved from this frame. Deferring both
    // transport kinds would discard a visible cross-kind carrier. Keep that
    // carrier unless a first fragment or completed datagram proves its child
    // has the same transport protocol.
    if fragment.fragment_offset != 0 && is_walkable_ipv6_extension(next_header) {
        return None;
    }
    let (ipv6_index, ipv6) = decoded
        .packet
        .iter()
        .take(fragment_index)
        .enumerate()
        .rev()
        .find_map(|(index, layer)| {
            layer
                .as_any()
                .downcast_ref::<Ipv6>()
                .map(|ipv6| (index, ipv6))
        })?;
    let ipv6_layout = decoded.layout.layer(ipv6_index)?;
    let payload_length = usize::from(ipv6.payload_length.exact().copied()?);
    let payload_end = ipv6_layout.range.end.checked_add(payload_length)?;
    let payload = decoded
        .layout
        .layer(fragment_index)
        .and_then(|layout| decoded.original.get(layout.range.end..payload_end))?;
    let mut cursor = 0usize;
    loop {
        if !is_walkable_ipv6_extension(next_header) {
            return Some(next_header);
        }
        let header = payload.get(cursor..)?;
        let (&following, &encoded_length) = header.first().zip(header.get(1))?;
        let length = ipv6_extension_header_length(next_header, encoded_length)
            .filter(|length| *length <= header.len())?;
        let next_cursor = cursor.checked_add(length)?;
        cursor = next_cursor;
        next_header = following;
    }
}

fn replayed_ipv6_encapsulation(decoded: &DecodedPacket) -> Vec<EncapsulationIdentifier> {
    let mut in_ipv6 = false;
    let mut replayed = Vec::new();
    for layer in decoded.packet.iter() {
        if layer.as_any().is::<Ipv4>() {
            in_ipv6 = false;
            replayed.clear();
        } else if layer.as_any().is::<Ipv6>() {
            in_ipv6 = true;
            replayed.clear();
        } else if layer.as_any().is::<Ipv6FragmentHeader>() {
            if in_ipv6 && ipv6_fragment(layer).is_some() {
                return replayed;
            }
        } else if in_ipv6 && let Some(ah) = layer.as_any().downcast_ref::<Ah>() {
            replayed.push(EncapsulationIdentifier::Ah { spi: ah.spi });
        }
    }
    Vec::new()
}

/// Number of leading derived layers already decoded on a physical fragment.
pub(crate) fn replayed_ip_prefix_layers(decoded: &DecodedPacket) -> usize {
    let mut ipv6_start = None;
    for (index, layer) in decoded.packet.iter().enumerate() {
        if layer.as_any().is::<Ipv4>() {
            ipv6_start = None;
            if ipv4_fragment(layer).is_some() {
                return 1;
            }
        } else if layer.as_any().is::<Ipv6>() {
            ipv6_start = Some(index);
        } else if ipv6_fragment(layer).is_some()
            && let Some(start) = ipv6_start
        {
            return index.saturating_sub(start);
        }
    }
    0
}
