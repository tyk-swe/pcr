// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conversation indexing and adapters from decoded layers to the session
//! crate's reassembly inputs.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::{
    Ah, AnalysisError, Bytes, DecodedPacket, Erspan, FlowKey, Fragment, FragmentKey, Geneve, Gre,
    Ipv4, Ipv6, Ipv6Fragment, L2tpv3, Layer, Mpls, Packet, Padding, Pppoe, Raw, Segment, Tcp, Udp,
    Vlan, Vlan8021ad, Vxlan,
};

/// Stable namespace surrounding a transport or fragmented datagram.
///
/// Components are taken only from decoded namespace identifiers that precede
/// the network header being indexed. The decoder's finite layer limit bounds
/// this vector.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnalysisScope {
    pub interface: Option<u32>,
    components: Vec<ScopeComponent>,
}

impl AnalysisScope {
    /// Stable outer encapsulation components, in wire order.
    pub fn components(&self) -> &[ScopeComponent] {
        &self.components
    }
}

/// One stable encapsulation namespace component.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ScopeComponent {
    Vlan {
        service: bool,
        id: u16,
    },
    OuterIp {
        first: IpAddr,
        second: IpAddr,
    },
    OuterTransport {
        protocol: u8,
        first: (IpAddr, u16),
        second: (IpAddr, u16),
    },
    Gre {
        protocol_type: Option<u16>,
        key: Option<u32>,
    },
    Vxlan {
        vni: u32,
    },
    Geneve {
        protocol_type: Option<u16>,
        vni: u32,
    },
    Mpls {
        label: u32,
    },
    Pppoe {
        session_id: u16,
    },
    Ah {
        spi: u32,
    },
    L2tpv3 {
        session_id: u32,
    },
    Erspan {
        version: u8,
        session_id: u16,
        vlan: u16,
    },
}

/// One conversation, with its two endpoints in a direction-neutral order.
///
/// Both directions of a flow map onto the same canonical value, which is what
/// lets one index describe the conversation an operator follows rather than
/// the two one-way flows the wire carries.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalFlow {
    pub scope: u64,
    pub first: (IpAddr, u16),
    pub second: (IpAddr, u16),
}

impl CanonicalFlow {
    pub fn from_flow(flow: &FlowKey) -> Self {
        let near = (flow.source, flow.source_port);
        let far = (flow.destination, flow.destination_port);
        if near <= far {
            Self {
                scope: flow.scope,
                first: near,
                second: far,
            }
        } else {
            Self {
                scope: flow.scope,
                first: far,
                second: near,
            }
        }
    }
}

/// First-seen conversation numbering, stable for a given input.
///
/// Indices are assigned in the order conversations first appear in the
/// capture, before any display filter is applied, so `tcp.stream 7` names the
/// same conversation whether or not the run was filtered — which is what lets
/// one command report an index and another extract it.
#[derive(Debug, Default)]
pub struct StreamIndex {
    assignments: BTreeMap<CanonicalFlow, u64>,
}

/// Run-local, first-seen numbering for typed capture namespaces.
#[derive(Debug, Default)]
pub(super) struct ScopeIndex {
    assignments: BTreeMap<AnalysisScope, u64>,
}

impl ScopeIndex {
    pub(super) fn assign(
        &mut self,
        scope: &AnalysisScope,
        number: u64,
        limit: usize,
        merge: bool,
    ) -> Result<u64, AnalysisError> {
        if merge {
            return Ok(0);
        }
        if let Some(index) = self.assignments.get(scope) {
            return Ok(*index);
        }
        if self.assignments.len() >= limit {
            return Err(AnalysisError::StreamLimit { number, limit });
        }
        let index = u64::try_from(self.assignments.len())
            .map_err(|_| AnalysisError::StreamLimit { number, limit })?;
        self.assignments.insert(scope.clone(), index);
        Ok(index)
    }
}

impl StreamIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the conversation index for `flow`, assigning the next index
    /// on first sight. `number` is the capture frame being processed and
    /// `max_flows` the table bound; exceeding it is an error rather than a
    /// silent misattribution.
    pub fn assign(
        &mut self,
        flow: &FlowKey,
        number: u64,
        max_flows: usize,
    ) -> Result<u64, AnalysisError> {
        let canonical = CanonicalFlow::from_flow(flow);
        if let Some(index) = self.assignments.get(&canonical) {
            return Ok(*index);
        }
        if self.assignments.len() >= max_flows {
            return Err(AnalysisError::StreamLimit {
                number,
                limit: max_flows,
            });
        }
        let index =
            u64::try_from(self.assignments.len()).map_err(|_| AnalysisError::StreamLimit {
                number,
                limit: max_flows,
            })?;
        self.assignments.insert(canonical, index);
        Ok(index)
    }

    pub fn get(&self, flow: &FlowKey) -> Option<u64> {
        self.assignments
            .get(&CanonicalFlow::from_flow(flow))
            .copied()
    }

    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Conversations in index order, for reporting.
    ///
    /// The table itself sorts by canonical endpoints, which is not the order
    /// indices were assigned in, so this reorders explicitly.
    pub fn conversations(&self) -> Vec<(&CanonicalFlow, u64)> {
        let mut all = self
            .assignments
            .iter()
            .map(|(flow, index)| (flow, *index))
            .collect::<Vec<_>>();
        all.sort_by_key(|(_, index)| *index);
        all
    }
}

/// The innermost transport of each kind in a decoded stack.
///
/// The innermost occurrence is the one an operator means: in a tunnelled
/// stack the outer encapsulation carries the inner conversation, and the
/// inner endpoints are the conversation's endpoints. The kinds are tracked
/// separately because an encapsulated frame legitimately belongs to both a
/// UDP conversation (the tunnel) and a TCP conversation (the payload).
pub(super) struct Transports<'a> {
    pub(super) tcp: Option<(usize, AnalysisScope, FlowKey, &'a Tcp)>,
    pub(super) udp: Option<(usize, AnalysisScope, FlowKey)>,
    /// Index of the outermost transport layer of either kind. In a
    /// same-transport tunnel this differs from the retained innermost
    /// occurrence, marking headers whose conversation carries no index.
    pub(super) outermost: Option<usize>,
}

pub(super) fn transports(decoded: &DecodedPacket) -> Transports<'_> {
    let mut scope = ScopeTracker::new(decoded.frame.interface);
    let mut found_tcp = None;
    let mut found_udp = None;
    let mut outermost = None;
    for (index, layer) in decoded.packet.iter().enumerate() {
        scope.observe(layer);
        if let Some(tcp) = layer.as_any().downcast_ref::<Tcp>() {
            if let Some(network) = scope.network {
                outermost.get_or_insert(index);
                let component_count = scope.components.len();
                found_tcp = Some((
                    index,
                    network,
                    component_count,
                    FlowKey {
                        scope: 0,
                        source: network.source,
                        source_port: tcp.source_port,
                        destination: network.destination,
                        destination_port: tcp.destination_port,
                    },
                    tcp,
                ));
            }
        } else if let Some(udp) = layer.as_any().downcast_ref::<Udp>()
            && let Some(network) = scope.network
        {
            outermost.get_or_insert(index);
            let component_count = scope.components.len();
            found_udp = Some((
                index,
                network,
                component_count,
                FlowKey {
                    scope: 0,
                    source: network.source,
                    source_port: udp.source_port,
                    destination: network.destination,
                    destination_port: udp.destination_port,
                },
            ));
        }
    }
    Transports {
        tcp: found_tcp.map(|(index, network, component_count, flow, tcp)| {
            (
                index,
                scope.analysis_scope(network, component_count),
                flow,
                tcp,
            )
        }),
        udp: found_udp.map(|(index, network, component_count, flow)| {
            (index, scope.analysis_scope(network, component_count), flow)
        }),
        outermost,
    }
}

fn canonical_ips(source: IpAddr, destination: IpAddr) -> (IpAddr, IpAddr) {
    if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    }
}

fn canonical_endpoints(
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
) -> ((IpAddr, u16), (IpAddr, u16)) {
    let source = (source, source_port);
    let destination = (destination, destination_port);
    if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    }
}

#[derive(Clone, Copy)]
struct CurrentNetwork {
    source: IpAddr,
    destination: IpAddr,
    component: usize,
}

struct ScopeTracker {
    interface: Option<u32>,
    components: Vec<ScopeComponent>,
    network: Option<CurrentNetwork>,
}

impl ScopeTracker {
    fn new(interface: Option<u32>) -> Self {
        Self {
            interface,
            components: Vec::new(),
            network: None,
        }
    }

    fn observe(&mut self, layer: &dyn Layer) -> Option<CurrentNetwork> {
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let source = IpAddr::V4(ipv4.source);
            let destination = IpAddr::V4(ipv4.destination);
            let (first, second) = canonical_ips(source, destination);
            let network = CurrentNetwork {
                source,
                destination,
                component: self.components.len(),
            };
            self.components
                .push(ScopeComponent::OuterIp { first, second });
            self.network = Some(network);
            return Some(network);
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let source = IpAddr::V6(ipv6.source);
            let destination = IpAddr::V6(ipv6.destination);
            let (first, second) = canonical_ips(source, destination);
            let network = CurrentNetwork {
                source,
                destination,
                component: self.components.len(),
            };
            self.components
                .push(ScopeComponent::OuterIp { first, second });
            self.network = Some(network);
            return Some(network);
        } else if let Some(tcp) = layer.as_any().downcast_ref::<Tcp>() {
            replace_outer_transport(
                &mut self.components,
                self.network.as_ref(),
                6,
                tcp.source_port,
                tcp.destination_port,
            );
        } else if let Some(udp) = layer.as_any().downcast_ref::<Udp>() {
            replace_outer_transport(
                &mut self.components,
                self.network.as_ref(),
                17,
                udp.source_port,
                udp.destination_port,
            );
        } else if let Some(vlan) = layer.as_any().downcast_ref::<Vlan>() {
            self.components.push(ScopeComponent::Vlan {
                service: false,
                id: vlan.vlan_id,
            });
        } else if let Some(vlan) = layer.as_any().downcast_ref::<Vlan8021ad>() {
            self.components.push(ScopeComponent::Vlan {
                service: true,
                id: vlan.vlan_id,
            });
        } else if let Some(gre) = layer.as_any().downcast_ref::<Gre>() {
            self.components.push(ScopeComponent::Gre {
                protocol_type: gre.protocol_type.exact().copied(),
                key: gre.key,
            });
        } else if let Some(vxlan) = layer.as_any().downcast_ref::<Vxlan>() {
            self.components
                .push(ScopeComponent::Vxlan { vni: vxlan.vni });
        } else if let Some(geneve) = layer.as_any().downcast_ref::<Geneve>() {
            self.components.push(ScopeComponent::Geneve {
                protocol_type: geneve.protocol_type.exact().copied(),
                vni: geneve.vni,
            });
        } else if let Some(mpls) = layer.as_any().downcast_ref::<Mpls>() {
            self.components
                .push(ScopeComponent::Mpls { label: mpls.label });
        } else if let Some(pppoe) = layer.as_any().downcast_ref::<Pppoe>() {
            self.components.push(ScopeComponent::Pppoe {
                session_id: pppoe.session_id,
            });
        } else if let Some(ah) = layer.as_any().downcast_ref::<Ah>() {
            self.components.push(ScopeComponent::Ah { spi: ah.spi });
        } else if let Some(l2tp) = layer.as_any().downcast_ref::<L2tpv3>() {
            self.components.push(ScopeComponent::L2tpv3 {
                session_id: l2tp.session_id,
            });
        } else if let Some(erspan) = layer.as_any().downcast_ref::<Erspan>() {
            self.components.push(ScopeComponent::Erspan {
                version: erspan.version,
                session_id: erspan.session_id,
                vlan: erspan.vlan,
            });
        }
        None
    }

    fn analysis_scope(&self, network: CurrentNetwork, component_count: usize) -> AnalysisScope {
        AnalysisScope {
            interface: self.interface,
            components: self
                .components
                .iter()
                .take(component_count)
                .enumerate()
                .filter(|(index, _)| *index != network.component)
                .map(|(_, component)| component.clone())
                .collect(),
        }
    }
}

fn replace_outer_transport(
    components: &mut [ScopeComponent],
    network: Option<&CurrentNetwork>,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
) {
    let Some(network) = network else {
        return;
    };
    let Some(component) = components.get_mut(network.component) else {
        return;
    };
    let (first, second) = canonical_endpoints(
        network.source,
        source_port,
        network.destination,
        destination_port,
    );
    *component = ScopeComponent::OuterTransport {
        protocol,
        first,
        second,
    };
}

/// The raw payload directly following the layer at `index`, if any.
///
/// Only fragment payloads use this: both built-in IP codecs force a true
/// fragment's payload to decode as a single raw layer, so the layer after
/// the fragmented header is the whole payload.
fn payload_after(packet: &Packet, index: usize) -> Bytes {
    packet
        .layer(index + 1)
        .and_then(|layer| layer.as_any().downcast_ref::<Raw>())
        .map(|raw| raw.bytes.clone())
        .unwrap_or_default()
}

/// The exact wire bytes of the TCP payload at `transport_index`.
///
/// The payload is reconstructed from the decode layout rather than from a
/// trailing raw layer, so it stays exact when a registry decodes the payload
/// into typed layers. Padding that a layer at or above the TCP layer already
/// excluded — link padding beyond the IP total length — is not stream data
/// and is left out; padding first excluded by a layer inside the payload is
/// stream data the inner protocol merely declined, and stays in.
pub(super) fn transport_payload(decoded: &DecodedPacket, transport_index: usize) -> Bytes {
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
pub fn tcp_segment(decoded: &DecodedPacket) -> Option<Segment> {
    scoped_tcp_segment(decoded).map(|(_, segment)| segment)
}

pub(super) fn scoped_tcp_segment(decoded: &DecodedPacket) -> Option<(AnalysisScope, Segment)> {
    tcp_segment_from_transport(decoded, transports(decoded).tcp?)
}

pub(super) fn tcp_segment_from_transport(
    decoded: &DecodedPacket,
    (index, scope, flow, tcp): (usize, AnalysisScope, FlowKey, &Tcp),
) -> Option<(AnalysisScope, Segment)> {
    Some((
        scope,
        Segment {
            flow,
            sequence: tcp.sequence,
            payload: transport_payload(decoded, index),
            syn: tcp.flags & Tcp::SYN != 0,
            fin: tcp.flags & Tcp::FIN != 0,
            rst: tcp.flags & Tcp::RST != 0,
        },
    ))
}

/// Maps a decoded stack onto the innermost UDP flow, when there is one.
pub fn udp_flow(decoded: &DecodedPacket) -> Option<FlowKey> {
    scoped_udp_flow(decoded).map(|(_, flow)| flow)
}

pub(super) fn scoped_udp_flow(decoded: &DecodedPacket) -> Option<(AnalysisScope, FlowKey)> {
    transports(decoded)
        .udp
        .map(|(_, scope, flow)| (scope, flow))
}

/// Maps a decoded stack onto an IP fragment awaiting reassembly.
///
/// Both built-in IP codecs refuse to descend into a fragmented payload, so a
/// true fragment's payload is always the raw layer that follows the network
/// header; an atomic fragment (offset zero and no more-fragments flag) needs
/// no reassembly and maps to nothing.
pub fn ip_fragment(decoded: &DecodedPacket) -> Option<Fragment> {
    scoped_ip_fragment(decoded).map(|(_, fragment)| fragment)
}

pub(super) fn scoped_ip_fragment(decoded: &DecodedPacket) -> Option<(AnalysisScope, Fragment)> {
    let mut scope = ScopeTracker::new(decoded.frame.interface);
    let mut ipv6_network = None;
    for (index, layer) in decoded.packet.iter().enumerate() {
        let network = scope.observe(layer);
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            if ipv4.more_fragments || ipv4.fragment_offset > 0 {
                return Some((
                    scope.analysis_scope(network?, scope.components.len()),
                    Fragment {
                        key: FragmentKey {
                            scope: 0,
                            source: ipv4.source.into(),
                            destination: ipv4.destination.into(),
                            identification: u32::from(ipv4.identification),
                            next_header: ipv4.protocol.exact().copied()?,
                        },
                        // IPv4 encodes the offset in eight-byte units.
                        offset: u32::from(ipv4.fragment_offset) * 8,
                        more_fragments: ipv4.more_fragments,
                        bytes: payload_after(&decoded.packet, index),
                    },
                ));
            }
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            ipv6_network = network.map(|network| {
                (
                    IpAddr::V6(ipv6.source),
                    IpAddr::V6(ipv6.destination),
                    network,
                )
            });
        } else if let Some(header) = layer.as_any().downcast_ref::<Ipv6Fragment>()
            && (header.more_fragments || header.fragment_offset > 0)
        {
            let (source, destination, network) = ipv6_network?;
            return Some((
                scope.analysis_scope(network, scope.components.len()),
                Fragment {
                    key: FragmentKey {
                        scope: 0,
                        source,
                        destination,
                        identification: header.identification,
                        next_header: header.next_header.exact().copied()?,
                    },
                    offset: u32::from(header.fragment_offset) * 8,
                    more_fragments: header.more_fragments,
                    bytes: payload_after(&decoded.packet, index),
                },
            ));
        }
    }
    None
}
