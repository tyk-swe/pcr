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
        validate_execution(batch, &execution)?;
        add_stats(&mut stats, &execution.stats, sequence)?;
        let processed = process_batch(
            batch,
            execution,
            registry,
            request.limits,
            &mut evidence_budget,
            &mut undecoded,
            &mut diagnostics,
        );
        any_response |= processed
            .probes
            .iter()
            .any(|probe| probe.status == TracerouteProbeStatus::Response);
        let reached = processed
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::DestinationReached));
        let unreachable = processed
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::Unreachable));
        hops.push(processed);
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

fn build_batches(
    request: &TracerouteRequest,
    address: IpAddr,
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
                address,
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
    super::clock::rate_delay(probes, rate).ok_or(TracerouteError::InvalidLimit {
        field: "probes_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

fn probe_packet(probe: &TracerouteProbe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                ttl: probe.hop_limit,
                identification: nonzero_ipv4_identification(probe.sequence),
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
                flow_label: (probe.sequence as u32) & 0x000f_ffff,
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

fn traceroute_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x54, (sequence >> 8) as u8, sequence as u8])
}

fn validate_execution(
    batch: &TracerouteBatch,
    execution: &TracerouteBatchExecution,
) -> Result<(), TracerouteError> {
    let sequence = batch.probes[0].sequence;
    if execution.sent.len() != batch.probes.len()
        || execution.sent_evidence.len() != batch.probes.len()
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: format!(
                "expected {} sent packets and frames, received {} packets and {} frames",
                batch.probes.len(),
                execution.sent.len(),
                execution.sent_evidence.len()
            ),
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index >= batch.probes.len())
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: "matched response references a request outside the hop batch".to_owned(),
        });
    }
    if execution.stats.packets_attempted != batch.probes.len() as u64
        || execution.stats.packets_completed != batch.probes.len() as u64
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: "successful exchange statistics do not account for every traceroute probe"
                .to_owned(),
        });
    }
    Ok(())
}

#[derive(Default)]
struct EvidenceBudget {
    frames: usize,
    bytes: usize,
}

impl EvidenceBudget {
    fn retain(
        &mut self,
        frame: &Frame,
        limits: TracerouteLimits,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    "traceroute evidence frame accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    "traceroute evidence byte accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    format!(
                        "traceroute evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                        limits.max_evidence_frames, limits.max_evidence_bytes
                    ),
                ),
            );
            return false;
        }
        self.frames = frames;
        self.bytes = bytes;
        true
    }
}

#[allow(clippy::too_many_arguments)]
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
                );
            }
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = evidence_budget
                .retain(&candidate.decoded.frame, limits, diagnostics)
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
        if evidence_budget.retain(&frame, limits, diagnostics) {
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
) {
    if candidate
        .decoded
        .frame
        .timestamp
        .duration_since(sent_at)
        .is_err()
    {
        return;
    }
    if best
        .as_ref()
        .is_none_or(|current| candidate.observation.kind.rank() > current.observation.kind.rank())
    {
        *best = Some(candidate);
    }
}
