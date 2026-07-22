#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracerouteResponseClassification {
    pub kind: TracerouteResponseKind,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Pure traceroute classifier. Corrupt, unrelated, pre-probe, and
/// protocol-inconsistent traffic returns `None` and cannot advance the trace.
pub fn classify_traceroute_response(
    registry: &ProtocolRegistry,
    strategy: TracerouteStrategy,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<TracerouteResponseClassification> {
    let observation = probe::observe(registry, strategy.probe_transport(), request, response)?;
    let destination = packet_destination(request, strategy)?;
    let kind = match observation.correlation {
        Correlation::TimeExceeded => TracerouteResponseKind::Intermediate,
        correlation if correlation.is_direct_reply() => {
            if observation.responder != destination {
                return None;
            }
            TracerouteResponseKind::DestinationReached
        }
        Correlation::PortUnreachable
            if strategy == TracerouteStrategy::Udp && observation.responder == destination =>
        {
            TracerouteResponseKind::DestinationReached
        }
        _ => TracerouteResponseKind::Unreachable,
    };
    Some(TracerouteResponseClassification {
        kind,
        responder: observation.responder,
        reason: observation.reason,
    })
}

fn packet_destination(packet: &Packet, strategy: TracerouteStrategy) -> Option<IpAddr> {
    let transport = match strategy {
        TracerouteStrategy::Tcp => Some(BuiltinProtocol::Tcp),
        TracerouteStrategy::Udp => Some(BuiltinProtocol::Udp),
        TracerouteStrategy::Icmp => None,
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

pub(super) fn add_stats(
    total: &mut Stats,
    batch: &Stats,
    sequence: u64,
) -> Result<(), TracerouteError> {
    total
        .checked_add(batch)
        .ok_or(TracerouteError::StatisticsOverflow { sequence })
}
use super::{
    Correlation, DecodedPacket, IpAddr, Packet, ProtocolRegistry, Stats, TracerouteError,
    TracerouteResponseKind, TracerouteStrategy, probe,
};
use crate::packet::semantics::{self, BuiltinProtocol};
