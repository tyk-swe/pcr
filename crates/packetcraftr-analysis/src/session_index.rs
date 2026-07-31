// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conversation indexing and adapters from decoded layers to the session
//! crate's reassembly inputs.

use std::collections::HashMap;
use std::net::IpAddr;

use super::{
    AnalysisError, Bytes, DecodedPacket, FlowKey, Ipv4, Ipv6, Packet, Padding, Segment, Tcp, Udp,
};

/// One conversation, with its two endpoints in a direction-neutral order.
///
/// Both directions of a flow map onto the same canonical value, which is what
/// lets one index describe the conversation an operator follows rather than
/// the two one-way flows the wire carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct CanonicalFlow {
    pub(super) first: (IpAddr, u16),
    pub(super) second: (IpAddr, u16),
}

impl CanonicalFlow {
    pub(super) fn from_flow(flow: &FlowKey) -> Self {
        let near = (flow.source, flow.source_port);
        let far = (flow.destination, flow.destination_port);
        if near <= far {
            Self {
                first: near,
                second: far,
            }
        } else {
            Self {
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
pub(super) struct StreamIndex {
    assignments: HashMap<CanonicalFlow, u64>,
}

impl StreamIndex {
    /// Returns the conversation index for `flow`, assigning the next index
    /// on first sight. `number` is the capture frame being processed and
    /// `max_flows` the table bound; exceeding it is an error rather than a
    /// silent misattribution.
    pub(super) fn assign(
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
        let index = self.assignments.len() as u64;
        self.assignments.insert(canonical, index);
        Ok(index)
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
    pub(super) tcp: Option<(usize, FlowKey, &'a Tcp)>,
    pub(super) udp: Option<(usize, FlowKey)>,
    /// Index of the outermost transport layer of either kind. In a
    /// same-transport tunnel this differs from the retained innermost
    /// occurrence, marking headers whose conversation carries no index.
    pub(super) outermost: Option<usize>,
}

pub(super) fn transports(packet: &Packet) -> Transports<'_> {
    let mut network: Option<(IpAddr, IpAddr)> = None;
    let mut found = Transports {
        tcp: None,
        udp: None,
        outermost: None,
    };
    for (index, layer) in packet.iter().enumerate() {
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            network = Some((ipv4.source.into(), ipv4.destination.into()));
        } else if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            network = Some((ipv6.source.into(), ipv6.destination.into()));
        } else if let Some(tcp) = layer.as_any().downcast_ref::<Tcp>() {
            if let Some((source, destination)) = network {
                found.outermost.get_or_insert(index);
                found.tcp = Some((
                    index,
                    FlowKey {
                        source,
                        source_port: tcp.source_port,
                        destination,
                        destination_port: tcp.destination_port,
                    },
                    tcp,
                ));
            }
        } else if let Some(udp) = layer.as_any().downcast_ref::<Udp>()
            && let Some((source, destination)) = network
        {
            found.outermost.get_or_insert(index);
            found.udp = Some((
                index,
                FlowKey {
                    source,
                    source_port: udp.source_port,
                    destination,
                    destination_port: udp.destination_port,
                },
            ));
        }
    }
    found
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
pub(super) fn tcp_segment(decoded: &DecodedPacket) -> Option<Segment> {
    let (index, flow, tcp) = transports(&decoded.packet).tcp?;
    Some(Segment {
        flow,
        sequence: tcp.sequence,
        payload: transport_payload(decoded, index),
        syn: tcp.flags & Tcp::SYN != 0,
        fin: tcp.flags & Tcp::FIN != 0,
        rst: tcp.flags & Tcp::RST != 0,
    })
}

/// Maps a decoded stack onto the innermost UDP flow, when there is one.
pub(super) fn udp_flow(decoded: &DecodedPacket) -> Option<FlowKey> {
    transports(&decoded.packet).udp.map(|(_, flow)| flow)
}
