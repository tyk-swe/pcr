// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{diagnostic::push_diagnostic_once, registry::Registry};

use crate::Stats;
use crate::clock::Clock;
use crate::probe::evidence::{
    EvidenceBudget, ResponseCandidate, push_undecoded_limit_diagnostic, response_within_deadline,
    retain_evidence, select_response_candidate,
};
use crate::target::{Authorizer, approve_operation, resolve_selected};

use super::error::DnsError;
use super::evidence::validate_dns_execution;
use super::model::{
    DnsAttemptEvidence, DnsExchange, DnsExecutor, DnsOutcome, DnsProbe, DnsRequest, DnsResult,
    DnsUndecodedEvidence,
};
use super::wire::{DnsResponseClassification, classify_dns_response, encode_dns_query};
use super::{DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_EVIDENCE_DIAGNOSTICS, MAX_DNS_PROBE_OVERHEAD};

/// Executes bounded DNS retries, repeating declared-name authorization,
/// resolution, and resolved-answer authorization before each probe.
pub fn dns<A, E, C>(
    request: &DnsRequest,
    authorizer: &mut A,
    registry: &Registry,
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
    approve_operation(
        authorizer,
        packet_count,
        maximum_wire_bytes,
        &deadline,
        duration_error,
    )?;

    let mut result = DnsResult {
        server: request.server.to_string(),
        server_port: request.server_port,
        resolved_addresses: Vec::new(),
        query_name,
        query_type: request.query_type,
        transaction_id: request.transaction_id,
        outcome: DnsOutcome::Timeout,
        response: None,
        attempts: Vec::with_capacity(usize::try_from(request.attempts).unwrap_or(usize::MAX)),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats::default(),
    };
    let mut evidence_budget = EvidenceBudget::default();
    let mut fallback_rank = 0u8;
    let mut scheduled_delay = Duration::ZERO;

    for attempt in 1..=request.attempts {
        if attempt != 1 {
            deadline.check()?;
            deadline.start_accounting(delay)?;
            clock.sleep(delay).map_err(|source| DnsError::Clock {
                attempt,
                message: source.to_string(),
            })?;
            deadline.account(delay)?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(DnsError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let resolved = resolve_selected(
            authorizer,
            &request.server,
            request.address_family,
            &deadline,
            duration_error,
        )?;
        result.server = resolved.declared;
        let addresses = resolved.addresses;
        if addresses.is_empty() {
            return Err(DnsError::Family {
                family: request.address_family.label(),
            });
        }
        for address in &addresses {
            if !result.resolved_addresses.contains(address) {
                result.resolved_addresses.push(*address);
            }
        }
        let address_index = (usize::try_from(attempt).unwrap_or(1) - 1) % addresses.len();
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
        deadline.start_accounting(Duration::ZERO)?;
        let execution_request = DnsExchange {
            probe: probe.clone(),
            timeout: request.timeout,
            max_responses: request.limits.max_evidence_frames,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        let execution = executor.execute(&execution_request);
        deadline.check()?;
        let execution = execution.map_err(|source| DnsError::Execution { attempt, source })?;
        if execution.permit != execution_request.permit {
            return Err(DnsError::InvalidEvidence {
                attempt,
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        deadline.account(execution.stats.elapsed)?;
        validate_dns_execution(&probe, &execution, request.limits, request.timeout)?;
        deadline.check()?;
        result
            .stats
            .checked_add(&execution.stats)
            .ok_or(DnsError::StatisticsOverflow { attempt })?;
        for diagnostic in execution.diagnostics {
            push_diagnostic_once(&mut result.diagnostics, diagnostic);
        }

        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let sent_packet = &execution.sent.built().packet;
        let mut best: Option<ResponseCandidate<'_, DnsResponseClassification>> = None;
        for matched in &execution.responses {
            deadline.check()?;
            if response_within_deadline(matched.latency, request.timeout)
                && let Some(classification) = classify_dns_response(
                    registry,
                    &probe,
                    sent_packet,
                    &matched.response,
                    request.limits,
                )
            {
                select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation: classification,
                        decoded: &matched.response,
                        latency: matched.latency,
                    },
                    request.timeout,
                    DnsResponseClassification::rank,
                    |_| (),
                );
            }
            deadline.check()?;
        }

        let evidence = if let Some(candidate) = best {
            let received_at = crate::live_timestamp(&candidate.decoded.frame);
            let latency = Some(candidate.latency);
            let response_frame = retain_evidence(
                &mut evidence_budget,
                &candidate.decoded.frame,
                DNS_EVIDENCE_DIAGNOSTICS,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
                &mut result.diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            let (status, response_code, reason) = match candidate.observation {
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
                    let status = if truncated {
                        DnsOutcome::Truncated
                    } else {
                        DnsOutcome::Response
                    };
                    result.outcome = status;
                    result.response = Some(response);
                    (status, response_code, reason)
                }
                DnsResponseClassification::NetworkFailure { reason } => {
                    let status = DnsOutcome::NetworkFailure;
                    update_dns_fallback(&mut result.outcome, &mut fallback_rank, status);
                    (status, None, reason)
                }
                DnsResponseClassification::DecodeFailure { reason } => {
                    let status = DnsOutcome::DecodeFailure;
                    update_dns_fallback(&mut result.outcome, &mut fallback_rank, status);
                    (status, None, reason)
                }
                DnsResponseClassification::Unrelated { reason } => {
                    let status = DnsOutcome::Unrelated;
                    update_dns_fallback(&mut result.outcome, &mut fallback_rank, status);
                    (status, None, reason)
                }
            };
            DnsAttemptEvidence {
                attempt,
                server_address,
                source_port,
                status,
                sent_at,
                received_at: Some(received_at),
                latency,
                response: response_frame,
                response_code,
                reason,
            }
        } else {
            DnsAttemptEvidence {
                attempt,
                server_address,
                source_port,
                status: DnsOutcome::Timeout,
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
            DnsOutcome::Response | DnsOutcome::Truncated
        );
        result.attempts.push(evidence);
        // Correlated response evidence has priority over ambient undecodable
        // frames under the one operation-wide retention budget.
        for frame in execution.undecoded {
            deadline.check()?;
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
            deadline.check()?;
        }
        if terminal {
            break;
        }
    }
    deadline.check()?;
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
    crate::clock::rate_delay(1, rate).ok_or(DnsError::InvalidLimit {
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

fn duration_error(actual: Duration, limit: Duration) -> DnsError {
    DnsError::DurationLimit { actual, limit }
}
