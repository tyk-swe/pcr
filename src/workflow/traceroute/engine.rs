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
    let operation = crate::operation::Context::generate().map_err(|source| {
        TracerouteError::Operation {
            sequence: 0,
            source,
        }
    })?;
    traceroute_streaming(
        request,
        &operation,
        authorizer,
        registry,
        executor,
        clock,
        &mut |_| Ok(()),
    )
}

/// Streaming traceroute entry point. One event is delivered after each hop is
/// classified, preserving earlier evidence if a later hop fails.
pub fn traceroute_streaming<A, E, C, S>(
    request: &TracerouteRequest,
    operation: &crate::operation::Context,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
    sink: &mut S,
) -> Result<TracerouteResult, TracerouteError>
where
    A: Authorizer,
    E: TracerouteExecutor,
    C: Clock,
    S: crate::operation::EventSink<TracerouteEvent>,
{
    operation
        .cancellation()
        .check()
        .map_err(|source| TracerouteError::Operation {
            sequence: 0,
            source,
        })?;
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

    let source_port = match request.strategy {
        TracerouteStrategy::Tcp => Some(
            operation
                .reserve_port(
                    "traceroute.tcp.source_port",
                    crate::operation::Transport::Tcp,
                )
                .map_err(|source| TracerouteError::Operation {
                    sequence: 0,
                    source,
                })?,
        ),
        TracerouteStrategy::Udp => Some(
            operation
                .reserve_port(
                    "traceroute.udp.source_port",
                    crate::operation::Transport::Udp,
                )
                .map_err(|source| TracerouteError::Operation {
                    sequence: 0,
                    source,
                })?,
        ),
        TracerouteStrategy::Icmp => None,
    };
    let batches = build_batches(request, operation.id(), source_port, destination)?;
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
        operation
            .cancellation()
            .check()
            .map_err(|source| TracerouteError::Operation { sequence, source })?;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            match clock.sleep_cancelled(delay, operation.cancellation()) {
                Ok(()) => {}
                Err(super::clock::SleepError::Clock(source)) => {
                    return Err(TracerouteError::Clock {
                        sequence,
                        message: source.to_string(),
                    });
                }
                Err(super::clock::SleepError::Cancelled(source)) => {
                    return Err(TracerouteError::Operation { sequence, source });
                }
            }
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
        let undecoded_start = undecoded.len();
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
        sink.emit(TracerouteEvent {
            first_sequence: sequence,
            hop: hop.clone(),
            undecoded: undecoded[undecoded_start..].to_vec(),
            stats: stats.clone(),
        })
        .map_err(|source| TracerouteError::Event { sequence, source })?;
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

fn build_batches(
    request: &TracerouteRequest,
    operation_id: crate::operation::Id,
    source_port: Option<u16>,
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
                operation_id,
                source_port,
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
                identification: probe.operation_id.derive_nonzero_u16(
                    "traceroute.ipv4.identification",
                    probe.sequence,
                ),
                ..Ipv4::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: probe.source_port.expect("generated UDP source port"),
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: probe.source_port.expect("generated TCP source port"),
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe
                        .operation_id
                        .derive_u32("traceroute.tcp.sequence", probe.sequence),
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv4 {
                    body: traceroute_identity(probe),
                    ..Icmpv4::default()
                }),
            };
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                hop_limit: probe.hop_limit,
                flow_label: probe
                    .operation_id
                    .derive_u32("traceroute.ipv6.flow_label", probe.sequence)
                    & 0x000f_ffff,
                ..Ipv6::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: probe.source_port.expect("generated UDP source port"),
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: probe.source_port.expect("generated TCP source port"),
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe
                        .operation_id
                        .derive_u32("traceroute.tcp.sequence", probe.sequence),
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv6 {
                    body: traceroute_identity(probe),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    packet
}

fn traceroute_identity(probe: &TracerouteProbe) -> Bytes {
    let identity = probe
        .operation_id
        .derive_u32("traceroute.icmp.identity", probe.sequence);
    Bytes::copy_from_slice(&identity.to_be_bytes())
}

fn validate_execution(
    batch: &TracerouteBatch,
    execution: &TracerouteBatchExecution,
    limits: TracerouteLimits,
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
    let captured_frames = checked_frame_count(&[
        execution.responses.len(),
        execution.unsolicited.len(),
        execution.undecoded.len(),
    ])
    .ok_or_else(|| TracerouteError::InvalidEvidence {
        sequence,
        message: "executor capture frame-count accounting overflowed".to_owned(),
    })?;
    if captured_frames > limits.max_evidence_frames {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: format!(
                "executor returned {captured_frames} captured frames beyond max_evidence_frames={}",
                limits.max_evidence_frames
            ),
        });
    }
    let captured_bytes = checked_frame_bytes(
        execution
            .responses
            .iter()
            .map(|response| &response.response.frame)
            .chain(execution.unsolicited.iter().map(|response| &response.frame))
            .chain(execution.undecoded.iter()),
    )
    .ok_or_else(|| TracerouteError::InvalidEvidence {
        sequence,
        message: "executor capture byte accounting overflowed".to_owned(),
    })?;
    if captured_bytes > limits.max_evidence_bytes {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: format!(
                "executor returned {captured_bytes} captured bytes beyond max_evidence_bytes={}",
                limits.max_evidence_bytes
            ),
        });
    }
    for (probe, (sent, evidence)) in batch
        .probes
        .iter()
        .zip(execution.sent.iter().zip(&execution.sent_evidence))
    {
        if !sent_traceroute_probe_matches(probe, sent) {
            return Err(TracerouteError::InvalidEvidence {
                sequence: probe.sequence,
                message:
                    "sent packet does not preserve the traceroute destination and probe identity"
                        .to_owned(),
            });
        }
        validate_frame(evidence, "sent").map_err(|message| TracerouteError::InvalidEvidence {
            sequence: probe.sequence,
            message,
        })?;
    }
    let sent_bytes = checked_sent_frame_bytes(&execution.sent_evidence).ok_or_else(|| {
        TracerouteError::InvalidEvidence {
            sequence,
            message: "sent frame byte accounting overflowed".to_owned(),
        }
    })?;
    if execution.stats.bytes != sent_bytes {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: format!(
                "successful exchange reported {} sent bytes for {sent_bytes} exact frame bytes",
                execution.stats.bytes
            ),
        });
    }
    for response in &execution.responses {
        validate_decoded_frame(&response.response, "matched response")
            .map_err(|message| TracerouteError::InvalidEvidence { sequence, message })?;
        if response.latency > batch.timeout {
            return Err(TracerouteError::InvalidEvidence {
                sequence,
                message: format!(
                    "matched response latency {:?} exceeds timeout {:?}",
                    response.latency, batch.timeout
                ),
            });
        }
    }
    for response in &execution.unsolicited {
        validate_decoded_frame(response, "unsolicited response")
            .map_err(|message| TracerouteError::InvalidEvidence { sequence, message })?;
    }
    for frame in &execution.undecoded {
        validate_frame(frame, "undecoded")
            .map_err(|message| TracerouteError::InvalidEvidence { sequence, message })?;
    }
    validate_capture_statistics(execution.stats.capture)
        .map_err(|message| TracerouteError::InvalidEvidence { sequence, message })?;
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

fn sent_traceroute_probe_matches(probe: &TracerouteProbe, sent: &Packet) -> bool {
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
    if !probe::packet_shape_matches(sent, &[network_protocol, transport_protocol]) {
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
                            == probe.operation_id.derive_nonzero_u16(
                                "traceroute.ipv4.identification",
                                probe.sequence,
                            )
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
                        && ipv6.flow_label
                            == probe
                                .operation_id
                                .derive_u32("traceroute.ipv6.flow_label", probe.sequence)
                                & 0x000f_ffff
                        && ipv6.hop_limit == probe.hop_limit
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.strategy {
        TracerouteStrategy::Udp => sent.get::<Udp>().is_some_and(|udp| {
            udp.source_port == probe.source_port.expect("generated UDP source port")
                && udp.destination_port == probe.destination_port.expect("validated UDP port")
        }),
        TracerouteStrategy::Tcp => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.source_port == probe.source_port.expect("generated TCP source port")
                && tcp.destination_port == probe.destination_port.expect("validated TCP port")
                && tcp.sequence
                    == probe
                        .operation_id
                        .derive_u32("traceroute.tcp.sequence", probe.sequence)
                && tcp.flags == Tcp::SYN
        }),
        TracerouteStrategy::Icmp => match probe.address {
            IpAddr::V4(_) => sent.get::<Icmpv4>().is_some_and(|icmp| {
                icmp.icmp_type == 8
                    && icmp.code == 0
                    && icmp.body == traceroute_identity(probe)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128
                    && icmp.code == 0
                    && icmp.body == traceroute_identity(probe)
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
    let error = match budget.retain(
        frame,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
    ) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let message = match error {
        EvidenceBudgetError::FrameCountOverflow => {
            "evidence_complete=false: traceroute evidence frame accounting overflowed; later frames were omitted".to_owned()
        }
        EvidenceBudgetError::ByteCountOverflow => {
            "evidence_complete=false: traceroute evidence byte accounting overflowed; later frames were omitted".to_owned()
        }
        EvidenceBudgetError::LimitExceeded => format!(
            "evidence_complete=false: traceroute evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
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
                            && (candidate.decoded.frame.bytes < current.decoded.frame.bytes
                                || (candidate.decoded.frame.bytes
                                    == current.decoded.frame.bytes
                                    && preferred_latency(
                                        candidate.latency,
                                        current.latency,
                                    ))))))))
}
