// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::time::{Duration, SystemTime};

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_packet::{
    Packet, decode::DecodedPacket, diagnostic::push_diagnostic_once, registry::ProtocolRegistry,
};

use crate::Stats;
use crate::kernel::clock::Clock;
use crate::kernel::evidence::{
    EvidenceBudget, ResponseCandidate, push_undecoded_limit_diagnostic, response_within_deadline,
    retain_evidence, select_response_candidate,
};
use crate::kernel::target::Authorizer;

use super::error::DnsError;
use super::evidence::validate_dns_execution;
use super::model::{
    DnsAttemptEvidence, DnsAttemptStatus, DnsExchange, DnsExecutor, DnsLimits, DnsOutcome,
    DnsProbe, DnsRequest, DnsResult, DnsUndecodedEvidence,
};
use super::wire::{DnsResponseClassification, classify_dns_response, encode_dns_query};
use super::{DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_EVIDENCE_DIAGNOSTICS, MAX_DNS_PROBE_OVERHEAD};

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
    let mut deadline = Deadline::new(request.limits.max_duration);
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
    enforce_deadline(&deadline)?;
    let authorization = authorizer.authorize_operation(packet_count, maximum_wire_bytes);
    enforce_deadline(&deadline)?;
    authorization?;

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
        enforce_deadline(&deadline)?;
        if attempt != 1 {
            enforce_deadline(&deadline)?;
            deadline.start_accounting(delay).map_err(duration_limit)?;
            clock.sleep(delay).map_err(|source| DnsError::Clock {
                attempt,
                message: source.to_string(),
            })?;
            deadline.account(delay).map_err(duration_limit)?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(DnsError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        enforce_deadline(&deadline)?;
        let resolved = authorizer.resolve_and_authorize(&request.server);
        enforce_deadline(&deadline)?;
        let resolved = resolved?;
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
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(duration_limit)?;
        let execution = executor.execute(&DnsExchange {
            probe: probe.clone(),
            timeout: request.timeout,
            max_responses: request.limits.max_evidence_frames,
        });
        enforce_deadline(&deadline)?;
        let execution = execution.map_err(|source| DnsError::Execution { attempt, source })?;
        deadline
            .account(execution.stats.elapsed)
            .map_err(duration_limit)?;
        validate_dns_execution(&probe, &execution, request.limits, request.timeout)?;
        enforce_deadline(&deadline)?;
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
                &deadline,
            )?;
        }
        for decoded in &execution.unsolicited {
            consider_dns_candidate(&mut best, &candidate_context, decoded, None, &deadline)?;
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
            enforce_deadline(&deadline)?;
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
            enforce_deadline(&deadline)?;
        }
        if terminal {
            break;
        }
    }
    enforce_deadline(&deadline)?;
    result.stats.elapsed =
        result
            .stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(DnsError::StatisticsOverflow {
                attempt: u32::try_from(result.attempts.len()).unwrap_or(u32::MAX),
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
    deadline: &Deadline,
) -> Result<(), DnsError> {
    enforce_deadline(deadline)?;
    if response_within_deadline(
        latency,
        decoded.frame.timestamp,
        context.sent_at,
        context.timeout,
    ) && let Some(classification) = classify_dns_response(
        context.registry,
        context.probe,
        context.sent,
        decoded,
        context.limits,
    ) {
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
    enforce_deadline(deadline)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "range_start plus a remainder modulo width stays inside the u16 ephemeral port \
              range the caller supplied"
)]
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
    crate::kernel::clock::rate_delay(1, rate).ok_or(DnsError::InvalidLimit {
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
fn enforce_deadline(deadline: &Deadline) -> Result<(), DnsError> {
    deadline.check().map_err(duration_limit)
}

fn duration_limit(error: DeadlineExceeded) -> DnsError {
    DnsError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}
