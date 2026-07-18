/// Executes a bounded DNS workflow through the shared policy, retry clock,
/// protocol registry, and exchange seams. Every retry repeats declared-name
/// authorization, resolution, and authorization of every answer before a new
/// probe is constructed.
pub fn dns<A, E, C>(
    request: &DnsRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<DnsResult, DnsError>
where
    A: Authorizer,
    E: DnsExecutor,
    C: Clock,
{
    let query_name = request.validate()?;
    let query = encode_dns_query(
        &query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
    )
    .map_err(DnsError::Query)?;
    let packet_count = u64::from(request.attempts);
    let per_probe_bytes = u64::try_from(query.len())
        .unwrap_or(u64::MAX)
        .saturating_add(MAX_DNS_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(per_probe_bytes)
            .ok_or(DnsError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
    let delay = dns_rate_delay(request.queries_per_second)?;
    let worst_case = request
        .timeout
        .checked_mul(request.attempts)
        .and_then(|duration| {
            delay
                .checked_mul(request.attempts.saturating_sub(1))
                .and_then(|delays| duration.checked_add(delays))
        })
        .ok_or(DnsError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    if worst_case > request.limits.max_duration {
        return Err(DnsError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    // This complete-operation gate deliberately precedes resolution and probe
    // construction. The authorizer's resolver path independently enforces the
    // declared hostname before every resolver side effect.
    authorizer.authorize_operation(packet_count, maximum_wire_bytes)?;

    let mut result = DnsResult {
        server: request.server.to_string(),
        server_port: request.server_port,
        resolved_addresses: Vec::new(),
        query_name,
        query_type: request.query_type,
        transaction_id: request.transaction_id,
        outcome: DnsOutcome::Timeout,
        response: None,
        attempts: Vec::with_capacity(request.attempts as usize),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats::default(),
    };
    let mut evidence_budget = EvidenceBudget::default();
    let mut fallback_rank = 0u8;
    let mut scheduled_delay = Duration::ZERO;

    for attempt in 1..=request.attempts {
        if attempt != 1 {
            clock.sleep(delay).map_err(|source| DnsError::Clock {
                attempt,
                message: source.to_string(),
            })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(DnsError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let resolved = authorizer.resolve_and_authorize(&request.server)?;
        result.server = resolved.declared;
        let addresses = resolved
            .addresses
            .into_iter()
            .filter(|address| request.address_family.accepts(*address))
            .fold(Vec::new(), |mut unique, address| {
                if !unique.contains(&address) {
                    unique.push(address);
                }
                unique
            });
        if addresses.is_empty() {
            return Err(DnsError::AddressFamily {
                family: request.address_family.label(),
            });
        }
        for address in &addresses {
            if !result.resolved_addresses.contains(address) {
                result.resolved_addresses.push(*address);
            }
        }
        let address_index = (attempt as usize - 1) % addresses.len();
        let server_address = addresses[address_index];
        let source_port = dns_source_port(request.source_port, attempt);
        let probe = DnsProbe {
            attempt,
            server_address,
            server_port: request.server_port,
            source_port,
            transaction_id: request.transaction_id,
            query_name: result.query_name.clone(),
            query_type: request.query_type,
            query: query.clone(),
        };
        let execution = executor
            .execute(&DnsExchange {
                probe: probe.clone(),
                timeout: request.timeout,
                max_responses: request.limits.max_evidence_frames,
            })
            .map_err(|source| DnsError::Execution { attempt, source })?;
        validate_dns_execution(&probe, &execution, request.limits, request.timeout)?;
        add_dns_stats(&mut result.stats, &execution.stats, attempt)?;
        for diagnostic in execution.diagnostics {
            push_diagnostic_once(&mut result.diagnostics, diagnostic);
        }

        let sent_at = execution.sent_evidence.timestamp;
        let mut best: Option<ResponseCandidate<'_, DnsResponseClassification>> = None;
        let candidate_context = DnsCandidateContext {
            registry,
            probe: &probe,
            sent: &execution.sent,
            sent_at,
            timeout: request.timeout,
            limits: request.limits,
        };
        for matched in &execution.responses {
            consider_dns_candidate(
                &mut best,
                &candidate_context,
                &matched.response,
                Some(matched.latency),
            );
        }
        for decoded in &execution.unsolicited {
            consider_dns_candidate(&mut best, &candidate_context, decoded, None);
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_at).ok());
            let response_frame = retain_evidence(
                &mut evidence_budget,
                &candidate.decoded.frame,
                DNS_EVIDENCE_DIAGNOSTICS,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
                &mut result.diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            match candidate.observation {
                DnsResponseClassification::Response(response) => {
                    let truncated = response.truncated;
                    let response_code = Some(response.response_code);
                    let reason = if truncated {
                        "validated DNS response set the truncation flag; partial records were not accepted"
                            .to_owned()
                    } else {
                        format!(
                            "validated DNS response with code {}",
                            response.response_code_name()
                        )
                    };
                    result.outcome = if truncated {
                        DnsOutcome::Truncated
                    } else {
                        DnsOutcome::Response
                    };
                    result.response = Some(response);
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: if truncated {
                            DnsAttemptStatus::Truncated
                        } else {
                            DnsAttemptStatus::Response
                        },
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code,
                        reason,
                    }
                }
                DnsResponseClassification::NetworkFailure { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::NetworkFailure,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::NetworkFailure,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
                DnsResponseClassification::DecodeFailure { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::DecodeFailure,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::DecodeFailure,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
                DnsResponseClassification::Unrelated { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::Unrelated,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::Unrelated,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
            }
        } else {
            DnsAttemptEvidence {
                attempt,
                server_address,
                source_port,
                status: DnsAttemptStatus::Timeout,
                sent_at,
                received_at: None,
                latency: None,
                response: None,
                response_code: None,
                reason: "no checksum-valid, tuple-correlated DNS response before the deadline"
                    .to_owned(),
            }
        };
        let terminal = matches!(
            evidence.status,
            DnsAttemptStatus::Response | DnsAttemptStatus::Truncated
        );
        result.attempts.push(evidence);
        // Correlated response evidence has priority over ambient undecodable
        // frames under the one operation-wide retention budget.
        for frame in execution.undecoded {
            if result.undecoded.len() >= request.limits.max_undecoded {
                push_undecoded_limit_diagnostic(
                    &mut result.diagnostics,
                    DNS_EVIDENCE_DIAGNOSTICS,
                    request.limits.max_undecoded,
                );
                break;
            }
            if retain_evidence(
                &mut evidence_budget,
                &frame,
                DNS_EVIDENCE_DIAGNOSTICS,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
                &mut result.diagnostics,
            ) {
                result
                    .undecoded
                    .push(DnsUndecodedEvidence { attempt, frame });
            }
        }
        if terminal {
            break;
        }
    }
    result.stats.elapsed =
        result
            .stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(DnsError::StatisticsOverflow {
                attempt: result.attempts.len() as u32,
            })?;
    Ok(result)
}

struct DnsCandidateContext<'a> {
    registry: &'a ProtocolRegistry,
    probe: &'a DnsProbe,
    sent: &'a Packet,
    sent_at: SystemTime,
    timeout: Duration,
    limits: DnsLimits,
}

fn consider_dns_candidate<'a>(
    best: &mut Option<ResponseCandidate<'a, DnsResponseClassification>>,
    context: &DnsCandidateContext<'_>,
    decoded: &'a DecodedPacket,
    latency: Option<Duration>,
) {
    if !response_within_deadline(
        latency,
        decoded.frame.timestamp,
        context.sent_at,
        context.timeout,
    ) {
        return;
    }
    let Some(classification) = classify_dns_response(
        context.registry,
        context.probe,
        context.sent,
        decoded,
        context.limits,
    ) else {
        return;
    };
    select_response_candidate(
        best,
        ResponseCandidate {
            observation: classification,
            decoded,
            latency,
        },
        context.sent_at,
        context.timeout,
        DnsResponseClassification::rank,
        |_| (),
    );
}

impl ResponseEvidence for DnsMatchedResponse {
    fn response(&self) -> &DecodedPacket {
        &self.response
    }

    fn latency(&self) -> Duration {
        self.latency
    }
}

pub(super) fn validate_dns_execution(
    probe: &DnsProbe,
    execution: &DnsExchangeExecution,
    limits: DnsLimits,
    timeout: Duration,
) -> Result<(), DnsError> {
    let attempt = probe.attempt;
    validate_frame(&execution.sent_evidence, "sent")
        .map_err(|message| DnsError::InvalidEvidence { attempt, message })?;
    let Some(network) = dns_network_envelope(&execution.sent) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no IPv4 or IPv6 tuple".to_owned(),
        });
    };
    let Some(ports) = dns_udp_ports(&execution.sent) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no complete UDP tuple".to_owned(),
        });
    };
    let network_protocol = if probe.server_address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    };
    if !super::probe::packet_shape_matches(&execution.sent, &[network_protocol, "udp", "raw"])
        || network.destination != probe.server_address
        || ports.source != probe.source_port
        || ports.destination != probe.server_port
        || raw_payload(&execution.sent).as_deref() != Some(probe.query.as_ref())
    {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet does not preserve the authorized server, UDP ports, and exact DNS query"
                .to_owned(),
        });
    }
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "successful exchange statistics must account for exactly one DNS query"
                .to_owned(),
        });
    }
    validate_sent_byte_accounting(
        std::slice::from_ref(&execution.sent_evidence),
        execution.stats.bytes,
    )
    .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_capture_statistics_evidence(execution.stats.capture)
        .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_response_frames_and_deadlines(
        &execution.responses,
        &execution.unsolicited,
        &execution.undecoded,
        timeout,
    )
    .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_aggregate_evidence_limits(
        &execution.responses,
        &execution.unsolicited,
        &execution.undecoded,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
    )
    .map_err(|error| map_dns_evidence_error(attempt, error))?;
    Ok(())
}

fn map_dns_evidence_error(attempt: u32, error: ExchangeEvidenceError) -> DnsError {
    let message = match error {
        ExchangeEvidenceError::CapturedFrameCountOverflow => {
            "executor frame-count accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameLimitExceeded { actual, limit } => {
            format!("executor returned {actual} frames beyond max_evidence_frames={limit}")
        }
        ExchangeEvidenceError::CapturedByteCountOverflow => {
            "executor frame-byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedByteLimitExceeded { actual, limit } => {
            format!("executor returned {actual} frame bytes beyond max_evidence_bytes={limit}")
        }
        ExchangeEvidenceError::SentByteCountOverflow => {
            "sent frame byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::SentByteCountMismatch { reported, actual } => format!(
            "successful exchange reported {reported} sent bytes for {actual} exact frame bytes"
        ),
        ExchangeEvidenceError::InvalidMatchedResponse { message }
        | ExchangeEvidenceError::InvalidUnsolicitedResponse { message }
        | ExchangeEvidenceError::InvalidUndecodedFrame { message }
        | ExchangeEvidenceError::InvalidCaptureStatistics { message } => message,
        ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::SentCardinality { .. }
        | ExchangeEvidenceError::MatchedResponseOutsideBatch
        | ExchangeEvidenceError::SentPacketMismatch { .. }
        | ExchangeEvidenceError::InvalidSentFrame { .. }
        | ExchangeEvidenceError::IncompleteStatistics => {
            unreachable!("DNS validation does not produce batch-only evidence errors")
        }
    };
    DnsError::InvalidEvidence { attempt, message }
}

fn dns_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let layer = packet
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))?;
    match layer.protocol_id().as_str() {
        "ipv4" => Some(NetworkEnvelope {
            source: IpAddr::V4(match layer.field("source")? {
                FieldValue::Ipv4(value) => value,
                _ => return None,
            }),
            destination: IpAddr::V4(match layer.field("destination")? {
                FieldValue::Ipv4(value) => value,
                _ => return None,
            }),
        }),
        "ipv6" => Some(NetworkEnvelope {
            source: IpAddr::V6(match layer.field("source")? {
                FieldValue::Ipv6(value) => value,
                _ => return None,
            }),
            destination: IpAddr::V6(match layer.field("destination")? {
                FieldValue::Ipv6(value) => value,
                _ => return None,
            }),
        }),
        _ => None,
    }
}

struct UdpPorts {
    source: u16,
    destination: u16,
}

fn dns_udp_ports(packet: &Packet) -> Option<UdpPorts> {
    let udp = packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "udp")?;
    Some(UdpPorts {
        source: u16::try_from(udp.field("source_port")?.as_u64()?).ok()?,
        destination: u16::try_from(udp.field("destination_port")?.as_u64()?).ok()?,
    })
}

pub(super) fn dns_source_port(base: u16, attempt: u32) -> u16 {
    let (range_start, width) = if base >= DNS_EPHEMERAL_SOURCE_PORT_BASE {
        (
            u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE),
            u32::from(u16::MAX) - u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE) + 1,
        )
    } else {
        (1, u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE) - 1)
    };
    let offset = attempt.saturating_sub(1) % width;
    (range_start + (u32::from(base) - range_start + offset) % width) as u16
}

fn dns_rate_delay(rate: Option<u32>) -> Result<Duration, DnsError> {
    crate::workflow::clock::rate_delay(1, rate).ok_or(DnsError::InvalidLimit {
        field: "queries_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

fn update_dns_fallback(outcome: &mut DnsOutcome, rank: &mut u8, candidate: DnsOutcome) {
    let candidate_rank = match candidate {
        DnsOutcome::NetworkFailure => 3,
        DnsOutcome::DecodeFailure => 2,
        DnsOutcome::Unrelated => 1,
        DnsOutcome::Timeout | DnsOutcome::Response | DnsOutcome::Truncated => 0,
    };
    if candidate_rank > *rank {
        *outcome = candidate;
        *rank = candidate_rank;
    }
}

fn add_dns_stats(total: &mut Stats, value: &Stats, attempt: u32) -> Result<(), DnsError> {
    total
        .checked_add(value)
        .ok_or(DnsError::StatisticsOverflow { attempt })
}
use super::Clock;
use super::wire::raw_payload;
use super::{
    Authorizer, DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_EVIDENCE_DIAGNOSTICS, DecodedPacket,
    DnsAttemptEvidence, DnsAttemptStatus, DnsError, DnsExchange, DnsExchangeExecution, DnsExecutor,
    DnsLimits, DnsMatchedResponse, DnsOutcome, DnsProbe, DnsRequest, DnsResponseClassification,
    DnsResult, DnsUndecodedEvidence, Duration, EvidenceBudget, ExchangeEvidenceError, FieldValue,
    IpAddr, MAX_DNS_PROBE_OVERHEAD, NetworkEnvelope, Packet, ProtocolRegistry, ResponseCandidate,
    ResponseEvidence, Stats, SystemTime, classify_dns_response, encode_dns_query,
    push_diagnostic_once, push_undecoded_limit_diagnostic, response_within_deadline,
    retain_evidence, select_response_candidate, validate_aggregate_evidence_limits,
    validate_capture_statistics_evidence, validate_frame, validate_response_frames_and_deadlines,
    validate_sent_byte_accounting,
};
