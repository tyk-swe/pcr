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
    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen_addresses = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        if request.address_family.accepts(address) && seen_addresses.insert(address) {
            addresses.push(address);
        }
    }
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
        let address_bytes =
            per_probe
                .checked_mul(address_probes)
                .ok_or(ScanError::InvalidLimit {
                    field: "wire_bytes",
                    value: u64::MAX,
                    reason: "wire-byte accounting overflowed".to_owned(),
                })?;
        total
            .checked_add(address_bytes)
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })
    })?;
    let worst_case = worst_case_duration(request, addresses.len(), endpoints_per_address)?;
    if worst_case > request.limits.max_duration {
        return Err(ScanError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    authorizer.authorize_operation(total_probes as u64, maximum_bytes)?;

    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect()
    };
    let batches = build_batches(request, &addresses, &endpoint_ports)?;

    let endpoints = addresses
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
    let endpoint_indices = endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| ((endpoint.address, endpoint.port), index))
        .collect::<HashMap<_, _>>();
    let mut output = ScanOutput {
        evidence_budget: EvidenceBudget::default(),
        endpoints,
        endpoint_indices,
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut stats = Stats::default();
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
        validate_exchange_evidence(batch, &exchange, request.limits)?;
        add_stats(&mut stats, &exchange.stats, sequence)?;
        process_batch(batch, exchange, registry, request.limits, &mut output);
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
        endpoints: output.endpoints,
        undecoded: output.undecoded,
        diagnostics: output.diagnostics,
        stats,
    })
}

pub(super) fn build_batches(
    request: &ScanRequest,
    addresses: &[IpAddr],
    endpoint_ports: &[Option<u16>],
) -> Result<Vec<ScanBatch>, ScanError> {
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
    address_count: usize,
    endpoints_per_address: usize,
) -> Result<Duration, ScanError> {
    let batches_per_attempt = endpoints_per_address.div_ceil(request.limits.batch_size);
    let batch_count = address_count
        .checked_mul(request.attempts as usize)
        .and_then(|count| count.checked_mul(batches_per_attempt))
        .ok_or(ScanError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| ScanError::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    })?;
    let exchange_time =
        request
            .timeout
            .checked_mul(batch_count_u32)
            .ok_or(ScanError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    let final_batch_size = endpoints_per_address % request.limits.batch_size;
    let delay =
        (0..batch_count.saturating_sub(1)).try_fold(Duration::ZERO, |total, batch_index| {
            let position = batch_index % batches_per_attempt;
            let probes = if position + 1 == batches_per_attempt && final_batch_size != 0 {
                final_batch_size
            } else {
                request.limits.batch_size
            };
            total
                .checked_add(rate_delay(probes, request.probes_per_second)?)
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
    crate::workflow::clock::rate_delay(probes, rate).ok_or(ScanError::InvalidLimit {
        field: "probes_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

pub(super) fn probe_packet(probe: &ScanProbe) -> Packet {
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

pub(super) fn validate_exchange_evidence(
    batch: &ScanBatch,
    exchange: &ScanBatchExecution,
    limits: ScanLimits,
) -> Result<(), ScanError> {
    validate_shared_exchange_evidence(
        ExchangeEvidence {
            request_count: batch.probes.len(),
            sent_packets: &exchange.sent,
            sent_frames: &exchange.sent_evidence,
            matched_responses: &exchange.responses,
            unsolicited: &exchange.unsolicited,
            undecoded: &exchange.undecoded,
            timeout: batch.timeout,
            stats: &exchange.stats,
        },
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        |request_index, sent| sent_scan_probe_matches(&batch.probes[request_index], sent),
    )
    .map_err(|error| map_scan_evidence_error(batch, error))
}

impl MatchedResponseEvidence for ScanMatchedResponse {
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

fn map_scan_evidence_error(batch: &ScanBatch, error: ExchangeEvidenceError) -> ScanError {
    let batch_sequence = batch.probes[0].sequence;
    let sequence = match &error {
        ExchangeEvidenceError::SentPacketMismatch { request_index }
        | ExchangeEvidenceError::InvalidSentFrame { request_index, .. } => {
            batch.probes[*request_index].sequence
        }
        _ => batch_sequence,
    };
    let message = format_exchange_evidence_error(error, "batch", "scan");
    ScanError::InvalidEvidence { sequence, message }
}

pub(super) fn sent_scan_probe_matches(probe: &ScanProbe, sent: &Packet) -> bool {
    let network_protocol = if probe.address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    };
    let transport_protocol = match probe.transport {
        ScanTransport::Tcp => "tcp",
        ScanTransport::Udp => "udp",
        ScanTransport::Icmp if probe.address.is_ipv4() => "icmpv4",
        ScanTransport::Icmp => "icmpv6",
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
                        && ipv4.identification == nonzero_ipv4_identification(probe.sequence)
                })
        }
        IpAddr::V6(destination) => {
            sent.iter()
                .filter(|layer| layer.protocol_id().as_str() == "ipv6")
                .count()
                == 1
                && sent.get::<Ipv6>().is_some_and(|ipv6| {
                    ipv6.destination == destination
                        && ipv6.flow_label == (probe.sequence as u32) & 0x000f_ffff
                })
        }
    };
    if !network_matches {
        return false;
    }
    match probe.transport {
        ScanTransport::Tcp => sent.get::<Tcp>().is_some_and(|tcp| {
            tcp.destination_port == probe.port.expect("validated TCP scan port")
                && tcp.sequence == probe.sequence as u32
                && tcp.flags == Tcp::SYN
        }),
        ScanTransport::Udp => sent.get::<Udp>().is_some_and(|udp| {
            udp.destination_port == probe.port.expect("validated UDP scan port")
        }),
        ScanTransport::Icmp => match probe.address {
            IpAddr::V4(_) => sent.get::<Icmpv4>().is_some_and(|icmp| {
                icmp.icmp_type == 8 && icmp.code == 0 && icmp.body == icmp_identity(probe.sequence)
            }),
            IpAddr::V6(_) => sent.get::<Icmpv6>().is_some_and(|icmp| {
                icmp.icmp_type == 128
                    && icmp.code == 0
                    && icmp.body == icmp_identity(probe.sequence)
            }),
        },
    }
}

struct ScanOutput {
    evidence_budget: EvidenceBudget,
    endpoints: Vec<ScanEndpointResult>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

fn process_batch(
    batch: &ScanBatch,
    exchange: ScanBatchExecution,
    registry: &ProtocolRegistry,
    limits: ScanLimits,
    output: &mut ScanOutput,
) {
    let ScanBatchExecution {
        sent,
        sent_evidence,
        mut responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = exchange;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(&mut output.diagnostics, diagnostic);
    }
    // Stable ordering retains executor order among responses for one request.
    responses.sort_by_key(|response| response.request_index);
    let mut matched_responses = responses.iter().peekable();

    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        let mut best = None;
        while matched_responses
            .peek()
            .is_some_and(|response| response.request_index == request_index)
        {
            let response = matched_responses
                .next()
                .expect("peeked matched response must remain available");
            if let Some(observation) =
                classify_scan_response(registry, probe.transport, built, &response.response)
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
                    |observation| observation.classification.rank(),
                    |observation| observation.responder,
                );
            }
        }
        for response in &unsolicited {
            if let Some(observation) =
                classify_scan_response(registry, probe.transport, built, response)
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
                    |observation| observation.classification.rank(),
                    |observation| observation.responder,
                );
            }
        }

        let endpoint_index = output
            .endpoint_indices
            .get(&(probe.address, probe.port))
            .copied()
            .expect("validated scan probe must have a result endpoint");
        let endpoint = &mut output.endpoints[endpoint_index];
        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = retain_evidence(
                &mut output.evidence_budget,
                &candidate.decoded.frame,
                "scan",
                limits.max_evidence_frames,
                limits.max_evidence_bytes,
                &mut output.diagnostics,
            )
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
        if output.undecoded.len() >= limits.max_undecoded {
            push_undecoded_limit_diagnostic(&mut output.diagnostics, "scan", limits.max_undecoded);
            break;
        }
        if retain_evidence(
            &mut output.evidence_budget,
            &frame,
            "scan",
            limits.max_evidence_frames,
            limits.max_evidence_bytes,
            &mut output.diagnostics,
        ) {
            output.undecoded.push(frame);
        }
    }
}

fn add_stats(total: &mut Stats, batch: &Stats, sequence: u64) -> Result<(), ScanError> {
    total
        .checked_add(batch)
        .ok_or(ScanError::StatisticsOverflow { sequence })
}
use super::{
    Authorizer, Bytes, Clock, DecodedPacket, Diagnostic, Duration, EvidenceBudget,
    ExchangeEvidence, ExchangeEvidenceError, Frame, HashMap, HashSet, IPV4_PROBE_BYTES,
    IPV6_PROBE_BYTES, Icmpv4, Icmpv6, IpAddr, Ipv4, Ipv6, MatchedResponseEvidence, Packet,
    ProtocolRegistry, ResponseCandidate, ScanBatch, ScanBatchExecution, ScanClassification,
    ScanEndpointResult, ScanError, ScanExecutor, ScanLimits, ScanMatchedResponse, ScanProbe,
    ScanProbeEvidence, ScanProbeStatus, ScanRequest, ScanResult, ScanTransport, Stats, Tcp, Udp,
    classify_scan_response, format_exchange_evidence_error, nonzero_ipv4_identification,
    push_diagnostic_once, push_undecoded_limit_diagnostic, retain_evidence,
    select_response_candidate, validate_shared_exchange_evidence,
};
