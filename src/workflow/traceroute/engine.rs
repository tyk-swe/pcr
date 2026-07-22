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
    let mut deadline = Deadline::new(request.limits.max_duration);
    request.validate()?;
    enforce_deadline(&deadline)?;
    let resolved = authorizer.resolve_and_authorize(&request.target);
    enforce_deadline(&deadline)?;
    let resolved = resolved?;
    let mut resolved_addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen_addresses = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        enforce_deadline(&deadline)?;
        if request.address_family.accepts(address) && seen_addresses.insert(address) {
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
    enforce_deadline(&deadline)?;
    let authorization = authorizer.authorize_operation(total_probes as u64, maximum_wire_bytes);
    enforce_deadline(&deadline)?;
    authorization?;

    let batches = build_batches(request, destination)?;
    enforce_deadline(&deadline)?;
    let mut hops = Vec::with_capacity(batches.len());
    let mut undecoded = Vec::new();
    let mut diagnostics = Vec::new();
    let mut stats = Stats::default();
    let mut evidence_budget = EvidenceBudget::default();
    let mut scheduled_delay = Duration::ZERO;
    let mut completion = TracerouteCompletion::MaximumHops;
    let mut any_response = false;

    for (batch_index, batch) in batches.iter().enumerate() {
        enforce_deadline(&deadline)?;
        let sequence = batch.probes[0].sequence;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            enforce_deadline(&deadline)?;
            deadline.start_accounting(delay).map_err(duration_limit)?;
            clock
                .sleep(delay)
                .map_err(|source| TracerouteError::Clock {
                    sequence,
                    message: source.to_string(),
                })?;
            deadline.account(delay).map_err(duration_limit)?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(TracerouteError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }

        enforce_deadline(&deadline)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor.execute(batch);
        enforce_deadline(&deadline)?;
        let execution =
            execution.map_err(|source| TracerouteError::Execution { sequence, source })?;
        deadline
            .account(execution.stats.elapsed)
            .map_err(duration_limit)?;
        validate_execution(batch, &execution, request.limits)?;
        enforce_deadline(&deadline)?;
        add_stats(&mut stats, &execution.stats, sequence)?;
        let mut evidence = TracerouteEvidenceState {
            budget: &mut evidence_budget,
            undecoded: &mut undecoded,
            diagnostics: &mut diagnostics,
        };
        let hop = process_batch(
            batch,
            execution,
            registry,
            request.limits,
            &mut evidence,
            &deadline,
        )?;
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
    enforce_deadline(&deadline)?;
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

impl ResponseEvidence for TracerouteMatchedResponse {
    fn response(&self) -> &DecodedPacket {
        &self.response
    }

    fn latency(&self) -> Duration {
        self.latency
    }
}

impl MatchedResponseEvidence for TracerouteMatchedResponse {
    fn request_index(&self) -> usize {
        self.request_index
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
    let message = format_exchange_evidence_error(error, "hop batch", "traceroute");
    TracerouteError::InvalidEvidence { sequence, message }
}

pub(super) fn sent_traceroute_probe_matches(probe: &TracerouteProbe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let transport_protocol = match probe.strategy {
        TracerouteStrategy::Tcp => BuiltinProtocol::Tcp,
        TracerouteStrategy::Udp => BuiltinProtocol::Udp,
        TracerouteStrategy::Icmp if probe.address.is_ipv4() => BuiltinProtocol::Icmpv4,
        TracerouteStrategy::Icmp => BuiltinProtocol::Icmpv6,
    };
    if !crate::workflow::probe::packet_shape_matches(sent, &[network_protocol, transport_protocol])
    {
        return false;
    }
    let network_matches = match probe.address {
        IpAddr::V4(destination) => {
            sent.iter()
                .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ipv4))
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
                .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ipv6))
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

struct TracerouteEvidenceState<'a> {
    budget: &'a mut EvidenceBudget,
    undecoded: &'a mut Vec<TracerouteUndecodedEvidence>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

fn process_batch(
    batch: &TracerouteBatch,
    execution: TracerouteBatchExecution,
    registry: &ProtocolRegistry,
    limits: TracerouteLimits,
    evidence: &mut TracerouteEvidenceState<'_>,
    deadline: &Deadline,
) -> Result<TracerouteHopResult, TracerouteError> {
    enforce_deadline(deadline)?;
    let TracerouteBatchExecution {
        sent,
        sent_evidence,
        mut responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = execution;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(evidence.diagnostics, diagnostic);
    }
    // Stable ordering retains executor order among responses for one request.
    responses.sort_by_key(|response| response.request_index);
    enforce_deadline(deadline)?;
    let mut matched_responses = responses.iter().peekable();

    let mut probes = Vec::with_capacity(batch.probes.len());
    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        enforce_deadline(deadline)?;
        let mut best = None;
        while matched_responses
            .peek()
            .is_some_and(|response| response.request_index == request_index)
        {
            enforce_deadline(deadline)?;
            let response = matched_responses
                .next()
                .expect("peeked matched response must remain available");
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, &response.response)
            {
                select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: &response.response,
                        latency: Some(response.latency),
                    },
                    sent_frame.timestamp,
                    batch.timeout,
                    |observation| observation.kind.rank(),
                    |observation| observation.responder,
                );
            }
            enforce_deadline(deadline)?;
        }
        for response in &unsolicited {
            enforce_deadline(deadline)?;
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, response)
            {
                select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response,
                        latency: None,
                    },
                    sent_frame.timestamp,
                    batch.timeout,
                    |observation| observation.kind.rank(),
                    |observation| observation.responder,
                );
            }
            enforce_deadline(deadline)?;
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = retain_evidence(
                evidence.budget,
                &candidate.decoded.frame,
                TRACEROUTE_EVIDENCE_DIAGNOSTICS,
                limits.max_evidence_frames,
                limits.max_evidence_bytes,
                evidence.diagnostics,
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
        enforce_deadline(deadline)?;
    }

    let hop_limit = batch.probes[0].hop_limit;
    for frame in batch_undecoded {
        enforce_deadline(deadline)?;
        if evidence.undecoded.len() >= limits.max_undecoded {
            push_undecoded_limit_diagnostic(
                evidence.diagnostics,
                TRACEROUTE_EVIDENCE_DIAGNOSTICS,
                limits.max_undecoded,
            );
            break;
        }
        if retain_evidence(
            evidence.budget,
            &frame,
            TRACEROUTE_EVIDENCE_DIAGNOSTICS,
            limits.max_evidence_frames,
            limits.max_evidence_bytes,
            evidence.diagnostics,
        ) {
            evidence
                .undecoded
                .push(TracerouteUndecodedEvidence { hop_limit, frame });
        }
        enforce_deadline(deadline)?;
    }
    Ok(TracerouteHopResult { hop_limit, probes })
}

fn enforce_deadline(deadline: &Deadline) -> Result<(), TracerouteError> {
    deadline.check().map_err(duration_limit)
}

fn duration_limit(error: DeadlineExceeded) -> TracerouteError {
    TracerouteError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}

use super::classification::add_stats;
use super::{
    Authorizer, Bytes, Clock, Deadline, DeadlineExceeded, DecodedPacket, Diagnostic, Duration,
    EvidenceBudget, ExchangeEvidence, ExchangeEvidenceError, HashSet, Icmpv4, Icmpv6, IpAddr, Ipv4,
    Ipv6, MAX_TRACEROUTE_PROBE_BYTES, MatchedResponseEvidence, Packet, ProtocolRegistry,
    ResponseCandidate, ResponseEvidence, Stats, TRACEROUTE_EVIDENCE_DIAGNOSTICS,
    TRACEROUTE_SOURCE_PORT, Tcp, TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion,
    TracerouteError, TracerouteExecutor, TracerouteHopResult, TracerouteLimits,
    TracerouteMatchedResponse, TracerouteProbe, TracerouteProbeEvidence, TracerouteProbeStatus,
    TracerouteRequest, TracerouteResponseKind, TracerouteResult, TracerouteStrategy,
    TracerouteUndecodedEvidence, Udp, classify_traceroute_response, format_exchange_evidence_error,
    nonzero_ipv4_identification, push_diagnostic_once, push_undecoded_limit_diagnostic,
    retain_evidence, select_response_candidate, validate_shared_exchange_evidence,
};
use crate::packet::semantics::BuiltinProtocol;
