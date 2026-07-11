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
    total.packets_attempted = add_stat(total.packets_attempted, batch.packets_attempted, sequence)?;
    total.packets_completed = add_stat(total.packets_completed, batch.packets_completed, sequence)?;
    total.bytes = add_stat(total.bytes, batch.bytes, sequence)?;
    total.elapsed = total
        .elapsed
        .checked_add(batch.elapsed)
        .ok_or(TracerouteError::StatisticsOverflow { sequence })?;
    for (target, value) in [
        (
            &mut total.capture.received_frames,
            batch.capture.received_frames,
        ),
        (
            &mut total.capture.received_bytes,
            batch.capture.received_bytes,
        ),
        (
            &mut total.capture.dropped_frames,
            batch.capture.dropped_frames,
        ),
        (
            &mut total.capture.dropped_bytes,
            batch.capture.dropped_bytes,
        ),
        (
            &mut total.capture.overflow_events,
            batch.capture.overflow_events,
        ),
        (
            &mut total.capture.receiver_dropped_frames,
            batch.capture.receiver_dropped_frames,
        ),
    ] {
        *target = add_stat(*target, value, sequence)?;
    }
    Ok(())
}

fn add_stat(left: u64, right: u64, sequence: u64) -> Result<u64, TracerouteError> {
    left.checked_add(right)
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
