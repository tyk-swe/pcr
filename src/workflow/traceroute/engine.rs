/// Resolves and authorizes the complete target set before constructing a
/// probe, approves the complete packet/byte/time budget, and preserves every
/// attempt until checksum-valid evidence reaches a terminal outcome.
pub fn traceroute<A, E, C>(
    request: &TracerouteRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<TracerouteResult, TracerouteError>
where
    A: Authorizer,
    E: TracerouteExecutor,
    C: Clock,
{
    request.validate()?;
    let resolved = authorizer.resolve_and_authorize(&request.target)?;
    let mut resolved_addresses = Vec::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        if request.address_family.accepts(address) && !resolved_addresses.contains(&address) {
            resolved_addresses.push(address);
        }
    }
    let Some(&destination) = resolved_addresses.first() else {
        return Err(TracerouteError::AddressFamily {
            family: request.address_family.label(),
        });
    };

    let total_probes = request.total_probe_count()?;
    if total_probes > request.limits.max_probes {
        return Err(TracerouteError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    if request.strategy == TracerouteStrategy::Udp {
        let base = request.destination_port.expect("validated UDP port");
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > u16::MAX as usize)
        {
            return Err(TracerouteError::InvalidPort {
                message: format!(
                    "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                    total_probes
                ),
            });
        }
    }
    let worst_case = worst_case_duration(request)?;
    if worst_case > request.limits.max_duration {
        return Err(TracerouteError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    let maximum_wire_bytes = (total_probes as u64)
        .checked_mul(MAX_TRACEROUTE_PROBE_BYTES)
        .ok_or(TracerouteError::InvalidLimit {
            field: "wire_bytes",
            value: u64::MAX,
            reason: "wire-byte accounting overflowed".to_owned(),
        })?;
    authorizer.authorize_operation(total_probes as u64, maximum_wire_bytes)?;

    let batches = build_batches(request, destination)?;
    let mut hops = Vec::with_capacity(batches.len());
    let mut undecoded = Vec::new();
    let mut diagnostics = Vec::new();
    let mut stats = Stats::default();
    let mut evidence_budget = EvidenceBudget::default();
    let mut scheduled_delay = Duration::ZERO;
    let mut completion = TracerouteCompletion::MaximumHops;
    let mut any_response = false;

    for (batch_index, batch) in batches.iter().enumerate() {
        let sequence = batch.probes[0].sequence;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            clock
                .sleep(delay)
                .map_err(|source| TracerouteError::Clock {
                    sequence,
                    message: source.to_string(),
                })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(TracerouteError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }

        let execution = executor
            .execute(batch)
            .map_err(|source| TracerouteError::Execution { sequence, source })?;
        validate_execution(batch, &execution, request.limits)?;
        add_stats(&mut stats, &execution.stats, sequence)?;
        let hop = process_batch(
            batch,
            execution,
            registry,
            request.limits,
            &mut evidence_budget,
            &mut undecoded,
            &mut diagnostics,
        );
        any_response |= hop
            .probes
            .iter()
            .any(|probe| probe.status == TracerouteProbeStatus::Response);
        let reached = hop
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::DestinationReached));
        let unreachable = hop
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::Unreachable));
        hops.push(hop);
        if reached {
            completion = TracerouteCompletion::DestinationReached;
            break;
        }
        if unreachable {
            completion = TracerouteCompletion::Unreachable;
            break;
        }
    }
    if completion == TracerouteCompletion::MaximumHops && !any_response {
        completion = TracerouteCompletion::Timeout;
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(TracerouteError::StatisticsOverflow {
                sequence: total_probes.saturating_sub(1) as u64,
            })?;

    Ok(TracerouteResult {
        target: resolved.declared,
        resolved_addresses,
        destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        hops,
        undecoded,
        completion,
        diagnostics,
        stats,
    })
}

pub(super) fn build_batches(
    request: &TracerouteRequest,
    destination: IpAddr,
) -> Result<Vec<TracerouteBatch>, TracerouteError> {
    let mut batches = Vec::with_capacity(request.hop_count());
    let mut sequence = 0_u64;
    for hop_limit in request.first_hop..=request.max_hops {
        let mut probes = Vec::with_capacity(request.probes_per_hop as usize);
        for attempt in 1..=request.probes_per_hop {
            let destination_port = match request.strategy {
                TracerouteStrategy::Udp => Some(
                    request
                        .destination_port
                        .expect("validated UDP port")
                        .checked_add(sequence as u16)
                        .expect("validated UDP probe port range"),
                ),
                TracerouteStrategy::Tcp => request.destination_port,
                TracerouteStrategy::Icmp => None,
            };
            probes.push(TracerouteProbe {
                sequence,
                address: destination,
                strategy: request.strategy,
                destination_port,
                hop_limit,
                attempt,
            });
            sequence = sequence
                .checked_add(1)
                .ok_or(TracerouteError::InvalidLimit {
                    field: "probes",
                    value: u64::MAX,
                    reason: "probe sequence overflowed".to_owned(),
                })?;
        }
        batches.push(TracerouteBatch {
            probes,
            timeout: request.timeout,
        });
    }
    Ok(batches)
}

fn worst_case_duration(request: &TracerouteRequest) -> Result<Duration, TracerouteError> {
    let hops = request.hop_count() as u32;
    let exchange = request
        .timeout
        .checked_mul(hops)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    let delay = rate_delay(request.probes_per_hop as usize, request.probes_per_second)?
        .checked_mul(hops.saturating_sub(1))
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    exchange
        .checked_add(delay)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, TracerouteError> {
    crate::workflow::clock::rate_delay(probes, rate).ok_or(TracerouteError::InvalidLimit {
        field: "probes_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

pub(super) fn probe_packet(probe: &TracerouteProbe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                ttl: probe.hop_limit,
                identification: nonzero_ipv4_identification(u64::from(
                    probe.hop_limit.saturating_sub(1),
                )),
                ..Ipv4::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe.sequence as u32,
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv4 {
                    body: traceroute_identity(probe.sequence),
                    ..Icmpv4::default()
                }),
            };
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                hop_limit: probe.hop_limit,
                flow_label: u32::from(probe.hop_limit),
                ..Ipv6::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe.sequence as u32,
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv6 {
                    body: traceroute_identity(probe.sequence),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    packet
}

pub(super) fn traceroute_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x54, (sequence >> 8) as u8, sequence as u8])
}

pub(super) fn validate_execution(
    batch: &TracerouteBatch,
    execution: &TracerouteBatchExecution,
    limits: TracerouteLimits,
) -> Result<(), TracerouteError> {
    validate_shared_exchange_evidence(
        ExchangeEvidence {
            request_count: batch.probes.len(),
            sent_packets: &execution.sent,
            sent_frames: &execution.sent_evidence,
            matched_responses: &execution.responses,
            unsolicited: &execution.unsolicited,
            undecoded: &execution.undecoded,
            timeout: batch.timeout,
            stats: &execution.stats,
        },
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        |request_index, sent| sent_traceroute_probe_matches(&batch.probes[request_index], sent),
    )
    .map_err(|error| map_traceroute_evidence_error(batch, error))
}

impl MatchedResponseEvidence for TracerouteMatchedResponse {
    fn request_index(&self) -> usize {
        self.request_index
    }

    fn response(&self) -> &DecodedPacket {
        &self.response
    }

    fn latency(&self) -> Duration {
        self.latency
    }
}

fn map_traceroute_evidence_error(
    batch: &TracerouteBatch,
    error: ExchangeEvidenceError,
) -> TracerouteError {
    let batch_sequence = batch.probes[0].sequence;
    let sequence = match &error {
        ExchangeEvidenceError::SentPacketMismatch { request_index }
        | ExchangeEvidenceError::InvalidSentFrame { request_index, .. } => {
            batch.probes[*request_index].sequence
        }
        _ => batch_sequence,
    };
    let message = match error {
        ExchangeEvidenceError::SentCardinality {
            expected,
            packets,
            frames,
        } => format!(
            "expected {expected} sent packets and frames, received {packets} packets and {frames} frames"
        ),
        ExchangeEvidenceError::MatchedResponseOutsideBatch => {
            "matched response references a request outside the hop batch".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameCountOverflow => {
            "executor capture frame-count accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured frames beyond max_evidence_frames={limit}")
        }
        ExchangeEvidenceError::CapturedByteCountOverflow => {
            "executor capture byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedByteLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured bytes beyond max_evidence_bytes={limit}")
        }
        ExchangeEvidenceError::SentPacketMismatch { .. } => {
            "sent packet does not preserve the traceroute destination and probe identity".to_owned()
        }
        ExchangeEvidenceError::InvalidSentFrame { message, .. }
        | ExchangeEvidenceError::InvalidMatchedResponse { message }
        | ExchangeEvidenceError::InvalidUnsolicitedResponse { message }
        | ExchangeEvidenceError::InvalidUndecodedFrame { message }
        | ExchangeEvidenceError::InvalidCaptureStatistics { message } => message,
        ExchangeEvidenceError::SentByteCountOverflow => {
            "sent frame byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::SentByteCountMismatch { reported, actual } => format!(
            "successful exchange reported {reported} sent bytes for {actual} exact frame bytes"
        ),
        ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::IncompleteStatistics => {
            "successful exchange statistics do not account for every traceroute probe".to_owned()
        }
    };
    TracerouteError::InvalidEvidence { sequence, message }
}

pub(super) fn sent_traceroute_probe_matches(probe: &TracerouteProbe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    };
    let transport_protocol = match probe.strategy {
        TracerouteStrategy::Tcp => "tcp",
        TracerouteStrategy::Udp => "udp",
        TracerouteStrategy::Icmp if probe.address.is_ipv4() => "icmpv4",
        TracerouteStrategy::Icmp => "icmpv6",
    };
    if !crate::workflow::probe::packet_shape_matches(sent, &[network_protocol, transport_protocol])
    {
        return false;
    }
    let network_matches = match probe.address {
        IpAddr::V4(destination) => {
            sent.iter()
                .filter(|layer| layer.protocol_id().as_str() == "ipv4")
                .count()
                == 1
                && sent.get::<Ipv4>().is_some_and(|ipv4| {
                    ipv4.destination == destination
                        && ipv4.identification
                            == nonzero_ipv4_identification(u64::from(
                                probe.hop_limit.saturating_sub(1),
                            ))
                        && ipv4.ttl == probe.hop_limit
                })
        }
        IpAddr::V6(destination) => {
            sent.iter()
                .filter(|layer| layer.protocol_id().as_str() == "ipv6")
                .count()
                == 1
                && sent.get::<Ipv6>().is_some_and(|ipv6| {
                    ipv6.destination == destination
                        && ipv6.flow_label == u32::from(probe.hop_limit)
                        && ipv6.hop_limit == probe.hop_limit
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.strategy {
        TracerouteStrategy::Udp => sent.get::<Udp>().is_some_and(|udp| {
            udp.source_port == TRACEROUTE_SOURCE_PORT
                && udp.destination_port == probe.destination_port.expect("validated UDP port")
        }),
        TracerouteStrategy::Tcp => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.source_port == TRACEROUTE_SOURCE_PORT
                && tcp.destination_port == probe.destination_port.expect("validated TCP port")
                && tcp.sequence == probe.sequence as u32
                && tcp.flags == Tcp::SYN
        }),
        TracerouteStrategy::Icmp => match probe.address {
            IpAddr::V4(_) => sent.get::<Icmpv4>().is_some_and(|icmp| {
                icmp.icmp_type == 8
                    && icmp.code == 0
                    && icmp.body == traceroute_identity(probe.sequence)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128
                    && icmp.code == 0
                    && icmp.body == traceroute_identity(probe.sequence)
            }),
        },
    }
}

fn retain_traceroute_evidence(
    budget: &mut EvidenceBudget,
    frame: &Frame,
    limits: TracerouteLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let error = match budget.retain(frame, limits.max_evidence_frames, limits.max_evidence_bytes) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let message = match error {
        EvidenceBudgetError::FrameCountOverflow => {
            "traceroute evidence frame accounting overflowed; later frames were omitted".to_owned()
        }
        EvidenceBudgetError::ByteCountOverflow => {
            "traceroute evidence byte accounting overflowed; later frames were omitted".to_owned()
        }
        EvidenceBudgetError::LimitExceeded => format!(
            "traceroute evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
            limits.max_evidence_frames, limits.max_evidence_bytes
        ),
    };
    push_diagnostic_once(
        diagnostics,
        Diagnostic::warning("traceroute.evidence_limit", message),
    );
    false
}

fn process_batch(
    batch: &TracerouteBatch,
    execution: TracerouteBatchExecution,
    registry: &ProtocolRegistry,
    limits: TracerouteLimits,
    evidence_budget: &mut EvidenceBudget,
    undecoded: &mut Vec<TracerouteUndecodedEvidence>,
    diagnostics: &mut Vec<Diagnostic>,
) -> TracerouteHopResult {
    let TracerouteBatchExecution {
        sent,
        sent_evidence,
        responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = execution;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(diagnostics, diagnostic);
    }

    let mut probes = Vec::with_capacity(batch.probes.len());
    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        let mut best = None;
        for response in responses
            .iter()
            .filter(|response| response.request_index == request_index)
        {
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, &response.response)
            {
                select_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: &response.response,
                        latency: Some(response.latency),
                    },
                    sent_frame.timestamp,
                    batch.timeout,
                );
            }
        }
        for response in &unsolicited {
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, response)
            {
                select_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response,
                        latency: None,
                    },
                    sent_frame.timestamp,
                    batch.timeout,
                );
            }
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = retain_traceroute_evidence(
                evidence_budget,
                &candidate.decoded.frame,
                limits,
                diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Response,
                response_kind: Some(candidate.observation.kind),
                responder: Some(candidate.observation.responder),
                sent_at: sent_frame.timestamp,
                received_at: Some(received_at),
                latency,
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Timeout,
                response_kind: None,
                responder: None,
                sent_at: sent_frame.timestamp,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        probes.push(evidence);
    }

    let hop_limit = batch.probes[0].hop_limit;
    for frame in batch_undecoded {
        if undecoded.len() >= limits.max_undecoded {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.undecoded_limit",
                    format!(
                        "undecodable traceroute evidence limit {} reached; later frames were omitted",
                        limits.max_undecoded
                    ),
                ),
            );
            break;
        }
        if retain_traceroute_evidence(evidence_budget, &frame, limits, diagnostics) {
            undecoded.push(TracerouteUndecodedEvidence { hop_limit, frame });
        }
    }
    TracerouteHopResult { hop_limit, probes }
}

struct ResponseCandidate<'a> {
    observation: TracerouteResponseClassification,
    decoded: &'a DecodedPacket,
    latency: Option<Duration>,
}

fn select_candidate<'a>(
    best: &mut Option<ResponseCandidate<'a>>,
    candidate: ResponseCandidate<'a>,
    sent_at: SystemTime,
    timeout: Duration,
) {
    if !response_within_deadline(
        candidate.latency,
        candidate.decoded.frame.timestamp,
        sent_at,
        timeout,
    ) {
        return;
    }
    if best
        .as_ref()
        .is_none_or(|current| traceroute_candidate_precedes(&candidate, current))
    {
        *best = Some(candidate);
    }
}

fn traceroute_candidate_precedes(
    candidate: &ResponseCandidate<'_>,
    current: &ResponseCandidate<'_>,
) -> bool {
    let candidate_rank = candidate.observation.kind.rank();
    let current_rank = current.observation.kind.rank();
    candidate_rank > current_rank
        || (candidate_rank == current_rank
            && (candidate.decoded.frame.timestamp < current.decoded.frame.timestamp
                || (candidate.decoded.frame.timestamp == current.decoded.frame.timestamp
                    && (candidate.observation.responder < current.observation.responder
                        || (candidate.observation.responder == current.observation.responder
                            && (candidate.decoded.frame.bytes()
                                < current.decoded.frame.bytes()
                                || (candidate.decoded.frame.bytes()
                                    == current.decoded.frame.bytes()
                                    && preferred_latency(candidate.latency, current.latency))))))))
}
use super::classification::add_stats;
use super::{
    Authorizer, Bytes, Clock, DecodedPacket, Diagnostic, Duration, EvidenceBudget,
    EvidenceBudgetError, ExchangeEvidence, ExchangeEvidenceError, Frame, Icmpv4, Icmpv6, IpAddr,
    Ipv4, Ipv6, MAX_TRACEROUTE_PROBE_BYTES, MatchedResponseEvidence, Packet, ProtocolRegistry,
    Stats, SystemTime, TRACEROUTE_SOURCE_PORT, Tcp, TracerouteBatch, TracerouteBatchExecution,
    TracerouteCompletion, TracerouteError, TracerouteExecutor, TracerouteHopResult,
    TracerouteLimits, TracerouteMatchedResponse, TracerouteProbe, TracerouteProbeEvidence,
    TracerouteProbeStatus, TracerouteRequest, TracerouteResponseClassification,
    TracerouteResponseKind, TracerouteResult, TracerouteStrategy, TracerouteUndecodedEvidence, Udp,
    classify_traceroute_response, nonzero_ipv4_identification, preferred_latency,
    push_diagnostic_once, response_within_deadline, validate_shared_exchange_evidence,
};
