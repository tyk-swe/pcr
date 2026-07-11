/// Resolves and authorizes the complete target set before constructing any
/// probe, applies operation-wide packet/byte/duration limits, schedules
/// homogeneous batches, and classifies only checksum-valid correlated facts.
pub fn scan<A, E, C>(
    request: &ScanRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<ScanResult, ScanError>
where
    A: Authorizer,
    E: ScanExecutor,
    C: Clock,
{
    let ports = request.validate()?;
    // Implementations must perform declared-target authorization before DNS
    // and authorize every answer before anything below constructs a ScanProbe.
    let resolved = authorizer.resolve_and_authorize(&request.target)?;
    if resolved.addresses.is_empty() {
        return Err(ScanError::AddressFamily {
            family: request.address_family.label(),
        });
    }
    let mut authorized_addresses = Vec::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        if !authorized_addresses.contains(&address) {
            authorized_addresses.push(address);
        }
    }
    let addresses = authorized_addresses
        .iter()
        .copied()
        .filter(|address| request.address_family.accepts(*address))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ScanError::AddressFamily {
            family: request.address_family.label(),
        });
    }

    let endpoints_per_address = if request.transport == ScanTransport::Icmp {
        1
    } else {
        ports.len()
    };
    let total_probes = addresses
        .len()
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(request.attempts as usize))
        .ok_or(ScanError::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe-count arithmetic overflowed".to_owned(),
        })?;
    if total_probes > request.limits.max_probes {
        return Err(ScanError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    let maximum_bytes = addresses.iter().try_fold(0_u64, |total, address| {
        let per_probe = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let address_probes = (endpoints_per_address as u64)
            .checked_mul(u64::from(request.attempts))
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
        total
            .checked_add(per_probe.saturating_mul(address_probes))
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })
    })?;
    authorizer.authorize_operation(total_probes as u64, maximum_bytes)?;

    let batches = build_batches(request, &addresses, &ports)?;
    let worst_case = worst_case_duration(request, &batches)?;
    if worst_case > request.limits.max_duration {
        return Err(ScanError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }

    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect()
    };
    let mut endpoints = addresses
        .iter()
        .flat_map(|address| {
            endpoint_ports.iter().map(move |port| ScanEndpointResult {
                address: *address,
                transport: request.transport,
                port: *port,
                classification: ScanClassification::Timeout,
                evidence: Vec::with_capacity(request.attempts as usize),
            })
        })
        .collect::<Vec<_>>();
    let mut diagnostics = Vec::new();
    let mut undecoded = Vec::new();
    let mut stats = Stats::default();
    let mut evidence_budget = EvidenceBudget::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        let sequence = batch.probes[0].sequence;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            clock.sleep(delay).map_err(|source| ScanError::Clock {
                sequence,
                message: source.to_string(),
            })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(ScanError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let exchange = executor
            .execute(batch)
            .map_err(|source| ScanError::Execution { sequence, source })?;
        validate_exchange_evidence(batch, &exchange)?;
        add_stats(&mut stats, &exchange.stats, sequence)?;
        process_batch(
            batch,
            exchange,
            registry,
            request.limits,
            &mut evidence_budget,
            &mut endpoints,
            &mut undecoded,
            &mut diagnostics,
        );
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(ScanError::StatisticsOverflow {
                sequence: total_probes.saturating_sub(1) as u64,
            })?;

    Ok(ScanResult {
        target: resolved.declared,
        resolved_addresses: addresses,
        endpoints,
        undecoded,
        diagnostics,
        stats,
    })
}

fn build_batches(
    request: &ScanRequest,
    addresses: &[IpAddr],
    ports: &[u16],
) -> Result<Vec<ScanBatch>, ScanError> {
    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect::<Vec<_>>()
    };
    let mut batches = Vec::new();
    let mut sequence = 0_u64;
    for address in addresses {
        for attempt in 1..=request.attempts {
            for chunk in endpoint_ports.chunks(request.limits.batch_size) {
                let probes = chunk
                    .iter()
                    .map(|port| {
                        let probe = ScanProbe {
                            sequence,
                            address: *address,
                            transport: request.transport,
                            port: *port,
                            attempt,
                        };
                        sequence = sequence.checked_add(1).ok_or(ScanError::InvalidLimit {
                            field: "probes",
                            value: u64::MAX,
                            reason: "probe sequence overflowed".to_owned(),
                        })?;
                        Ok(probe)
                    })
                    .collect::<Result<Vec<_>, ScanError>>()?;
                batches.push(ScanBatch {
                    probes,
                    timeout: request.timeout,
                });
            }
        }
    }
    Ok(batches)
}

fn worst_case_duration(
    request: &ScanRequest,
    batches: &[ScanBatch],
) -> Result<Duration, ScanError> {
    let exchange_time =
        request
            .timeout
            .checked_mul(batches.len() as u32)
            .ok_or(ScanError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    let delay = batches
        .iter()
        .take(batches.len().saturating_sub(1))
        .try_fold(Duration::ZERO, |total, batch| {
            total
                .checked_add(rate_delay(batch.probes.len(), request.probes_per_second)?)
                .ok_or(ScanError::DurationLimit {
                    actual: Duration::MAX,
                    limit: request.limits.max_duration,
                })
        })?;
    exchange_time
        .checked_add(delay)
        .ok_or(ScanError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, ScanError> {
    let Some(rate) = rate else {
        return Ok(Duration::ZERO);
    };
    let nanos = (probes as u128)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u128::from(rate) - 1))
        .map(|value| value / u128::from(rate))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ScanError::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        })?;
    Ok(Duration::from_nanos(nanos))
}

fn probe_packet(probe: &ScanProbe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                identification: nonzero_ipv4_identification(probe.sequence),
                ..Ipv4::default()
            });
            match probe.transport {
                ScanTransport::Tcp => packet.push(Tcp {
                    destination_port: probe.port.expect("validated TCP scan port"),
                    sequence: probe.sequence as u32,
                    ..Tcp::default()
                }),
                ScanTransport::Udp => packet.push(Udp {
                    destination_port: probe.port.expect("validated UDP scan port"),
                    ..Udp::default()
                }),
                ScanTransport::Icmp => packet.push(Icmpv4 {
                    body: icmp_identity(probe.sequence),
                    ..Icmpv4::default()
                }),
            };
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                flow_label: (probe.sequence as u32) & 0x000f_ffff,
                ..Ipv6::default()
            });
            match probe.transport {
                ScanTransport::Tcp => packet.push(Tcp {
                    destination_port: probe.port.expect("validated TCP scan port"),
                    sequence: probe.sequence as u32,
                    ..Tcp::default()
                }),
                ScanTransport::Udp => packet.push(Udp {
                    destination_port: probe.port.expect("validated UDP scan port"),
                    ..Udp::default()
                }),
                ScanTransport::Icmp => packet.push(Icmpv6 {
                    body: icmp_identity(probe.sequence),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    packet
}

fn icmp_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x43, (sequence >> 8) as u8, sequence as u8])
}

fn validate_exchange_evidence(
    batch: &ScanBatch,
    exchange: &ScanBatchExecution,
) -> Result<(), ScanError> {
    let sequence = batch.probes[0].sequence;
    if exchange.sent.len() != batch.probes.len()
        || exchange.sent_evidence.len() != batch.probes.len()
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: format!(
                "expected {} sent packets and frames, received {} packets and {} frames",
                batch.probes.len(),
                exchange.sent.len(),
                exchange.sent_evidence.len()
            ),
        });
    }
    if exchange
        .responses
        .iter()
        .any(|response| response.request_index >= batch.probes.len())
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: "matched response references a request outside the batch".to_owned(),
        });
    }
    if exchange.stats.packets_attempted != batch.probes.len() as u64
        || exchange.stats.packets_completed != batch.probes.len() as u64
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: "successful exchange statistics do not account for every scan probe"
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
        limits: ScanLimits,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    "scan evidence frame accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    "scan evidence byte accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    format!(
                        "scan evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
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
    batch: &ScanBatch,
    exchange: ScanBatchExecution,
    registry: &ProtocolRegistry,
    limits: ScanLimits,
    evidence_budget: &mut EvidenceBudget,
    endpoints: &mut [ScanEndpointResult],
    undecoded: &mut Vec<Frame>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let ScanBatchExecution {
        sent,
        sent_evidence,
        responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = exchange;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(diagnostics, diagnostic);
    }

    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        let mut best: Option<ResponseCandidate<'_>> = None;
        for response in responses
            .iter()
            .filter(|response| response.request_index == request_index)
        {
            if let Some(observation) =
                classify_scan_response(registry, probe.transport, built, &response.response)
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
                classify_scan_response(registry, probe.transport, built, response)
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

        let endpoint = endpoints
            .iter_mut()
            .find(|endpoint| {
                endpoint.address == probe.address
                    && endpoint.transport == probe.transport
                    && endpoint.port == probe.port
            })
            .expect("validated scan probe must have a result endpoint");
        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = evidence_budget
                .retain(&candidate.decoded.frame, limits, diagnostics)
                .then(|| candidate.decoded.frame.clone());
            if candidate.observation.classification.rank() > endpoint.classification.rank() {
                endpoint.classification = candidate.observation.classification;
            }
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Response,
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at: sent_frame.timestamp,
                received_at: Some(received_at),
                latency,
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Timeout,
                classification: ScanClassification::Timeout,
                responder: None,
                sent_at: sent_frame.timestamp,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        endpoint.evidence.push(evidence);
    }

    for frame in batch_undecoded {
        if undecoded.len() >= limits.max_undecoded {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.undecoded_limit",
                    format!(
                        "undecodable scan evidence limit {} reached; later frames were omitted",
                        limits.max_undecoded
                    ),
                ),
            );
            break;
        }
        if evidence_budget.retain(&frame, limits, diagnostics) {
            undecoded.push(frame);
        }
    }
}

struct ResponseCandidate<'a> {
    observation: ScanResponseClassification,
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
    if best.as_ref().is_none_or(|current| {
        candidate.observation.classification.rank() > current.observation.classification.rank()
    }) {
        *best = Some(candidate);
    }
}

fn add_stats(total: &mut Stats, batch: &Stats, sequence: u64) -> Result<(), ScanError> {
    total.packets_attempted = add_stat(total.packets_attempted, batch.packets_attempted, sequence)?;
    total.packets_completed = add_stat(total.packets_completed, batch.packets_completed, sequence)?;
    total.bytes = add_stat(total.bytes, batch.bytes, sequence)?;
    total.elapsed = total
        .elapsed
        .checked_add(batch.elapsed)
        .ok_or(ScanError::StatisticsOverflow { sequence })?;
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

fn add_stat(left: u64, right: u64, sequence: u64) -> Result<u64, ScanError> {
    left.checked_add(right)
        .ok_or(ScanError::StatisticsOverflow { sequence })
}

fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}
