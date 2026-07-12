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
    let destination = packet_destination(request)?;
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

fn packet_destination(packet: &Packet) -> Option<IpAddr> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        match layer.field("destination")? {
            FieldValue::Ipv4(value) => Some(IpAddr::V4(value)),
            FieldValue::Ipv6(value) => Some(IpAddr::V6(value)),
            _ => None,
        }
    })
}

fn add_stats(total: &mut Stats, batch: &Stats, sequence: u64) -> Result<(), TracerouteError> {
    total
        .checked_add(batch)
        .ok_or(TracerouteError::StatisticsOverflow { sequence })
}

fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}
