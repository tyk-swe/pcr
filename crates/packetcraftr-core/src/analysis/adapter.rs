// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-specific decoded-layer inspection and reassembly input adapters.

use std::net::IpAddr;

use crate::Packet;
use crate::decode::Result as DecodedPacket;
use crate::layer::Padding;
use crate::protocol::network::{Ipv4, Ipv6};
use crate::protocol::transport::{Tcp, Udp};
use bytes::Bytes;

use crate::analysis::reassembly::tcp::{FlowKey, Segment};

/// The innermost transport of each kind in a decoded stack.
///
/// The innermost occurrence is the one an operator means: in a tunnelled
/// stack the outer encapsulation carries the inner conversation, and the
/// inner endpoints are the conversation's endpoints. The kinds are tracked
/// separately because an encapsulated frame legitimately belongs to both a
/// UDP conversation (the tunnel) and a TCP conversation (the payload).
pub(crate) struct Transports<'a> {
    pub(crate) tcp: Option<(usize, FlowKey, &'a Tcp)>,
    pub(crate) udp: Option<(usize, FlowKey)>,
    /// Index of the outermost transport layer of either kind. In a
    /// same-transport tunnel this differs from the retained innermost
    /// occurrence, marking headers whose conversation carries no index.
    pub(crate) outermost: Option<usize>,
}

pub(crate) fn transports(packet: &Packet) -> Transports<'_> {
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
pub(crate) fn tcp_segment(decoded: &DecodedPacket) -> Option<Segment> {
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
pub(crate) fn udp_flow(decoded: &DecodedPacket) -> Option<FlowKey> {
    transports(&decoded.packet).udp.map(|(_, flow)| flow)
}
