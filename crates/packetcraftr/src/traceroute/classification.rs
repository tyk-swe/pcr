// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::protocol::semantics;
use packetcraftr_core::{decode::DecodedPacket, packet::Packet, registry::Registry};

use crate::probe::{self, Correlation, Transport};

use super::ResponseKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseClassification {
    pub kind: ResponseKind,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Pure traceroute classifier. Corrupt, unrelated, pre-probe, and
/// protocol-inconsistent traffic returns `None` and cannot advance the trace.
pub fn classify_response(
    registry: &Registry,
    strategy: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<ResponseClassification> {
    let observation = probe::observe(registry, strategy, request, response)?;
    let destination = packet_destination(request, strategy)?;
    let kind = match observation.correlation {
        Correlation::TimeExceeded => ResponseKind::Intermediate,
        correlation if correlation.is_direct_reply() => {
            if observation.responder != destination {
                return None;
            }
            ResponseKind::DestinationReached
        }
        Correlation::PortUnreachable
            if strategy == Transport::Udp && observation.responder == destination =>
        {
            ResponseKind::DestinationReached
        }
        _ => ResponseKind::Unreachable,
    };
    Some(ResponseClassification {
        kind,
        responder: observation.responder,
        reason: observation.reason,
    })
}

fn packet_destination(packet: &Packet, strategy: Transport) -> Option<IpAddr> {
    let transport = match strategy {
        Transport::Tcp => Some(BuiltinProtocol::Tcp),
        Transport::Udp => Some(BuiltinProtocol::Udp),
        Transport::Icmp => None,
    };
    let transport_index = packet.iter().position(|layer| match transport {
        Some(transport) => BuiltinProtocol::of(layer) == Some(transport),
        None => matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)
        ),
    })?;
    let path = semantics::enclosing_ip_path(packet, transport_index).ok()??;
    Some(path.final_destination)
}
