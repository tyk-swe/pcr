// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::registry::Registry;

use crate::BoundaryError;
use crate::Stats;
use crate::clock::Clock;
use crate::evidence::Budget;
use crate::probe::evidence::{
    ResponseCandidate, push_undecoded_limit_diagnostic, response_within_deadline, retain_evidence,
    update_best_candidate,
};
use crate::target::{Authorizer, approve_operation, resolve_selected};

use super::error::Error;
use super::evidence::validate_dns_execution;
use super::model::{
    AttemptEvidence, Event, Exchange, Execution, Executor, Limits, Outcome, Probe, Record, Request,
    ResponseSummary, Result, Section, Summary, UndecodedEvidence, ValidatedResponse,
};
use super::wire::{ResponseClassification, classify_response, encode_query};
use super::{DNS_EPHEMERAL_SOURCE_PORT_BASE, DNS_EVIDENCE_DIAGNOSTICS, MAX_DNS_PROBE_OVERHEAD};

/// Executes bounded DNS retries, repeating declared-name authorization,
/// resolution, and resolved-answer authorization before each probe.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> std::result::Result<Result, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
{
    let mut collector = Collector::default();
    let summary = run_with_events(request, authorizer, registry, executor, clock, |event| {
        collector.observe(event);
        Ok(())
    })?;
    Ok(collector.finish(summary))
}

/// Executes one approved DNS retry sequence and publishes attempts, accepted
/// and rejected records, and retained undecoded evidence as they become final.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
    let PreparedOperation {
        deadline,
        query,
        delay,
        summary,
    } = prepare_operation(request, authorizer)?;
    Operation {
        request,
        authorizer,
        registry,
        executor,
        clock,
        deadline,
        query,
        delay,
        summary,
        evidence_budget: Budget::default(),
        fallback_rank: 0,
        scheduled_delay: Duration::ZERO,
        attempts_completed: 0,
        retained_undecoded: 0,
        emit: &mut emit,
    }
    .execute()
}

#[derive(Default)]
struct Collector {
    attempts: Vec<AttemptEvidence>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    rejected: Vec<super::model::RejectedRecord>,
    undecoded: Vec<UndecodedEvidence>,
}

impl Collector {
    fn observe(&mut self, event: Event) {
        match event {
            Event::Attempt { evidence, .. } => self.attempts.push(evidence),
            Event::Record {
                section, record, ..
            } => match section {
                Section::Answer => self.answers.push(record),
                Section::Authority => self.authorities.push(record),
                Section::Additional => self.additionals.push(record),
            },
            Event::Rejected { record, .. } => self.rejected.push(record),
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
        }
    }

    fn finish(self, summary: Summary) -> Result {
        let response = summary.response.map(|response| ValidatedResponse {
            transaction_id: response.transaction_id,
            response_code: response.response_code,
            edns: response.edns,
            authoritative: response.authoritative,
            truncated: response.truncated,
            recursion_desired: response.recursion_desired,
            recursion_available: response.recursion_available,
            authenticated_data: response.authenticated_data,
            checking_disabled: response.checking_disabled,
            answers: self.answers,
            authorities: self.authorities,
            additionals: self.additionals,
            rejected_records: self.rejected,
            rejected_record_count: response.rejected_record_count,
        });
        Result {
            server: summary.server,
            server_port: summary.server_port,
            resolved_addresses: summary.resolved_addresses,
            query_name: summary.query_name,
            query_type: summary.query_type,
            transaction_id: summary.transaction_id,
            outcome: summary.outcome,
            response,
            attempts: self.attempts,
            undecoded: self.undecoded,
            diagnostics: summary.diagnostics,
            stats: summary.stats,
        }
    }
}

struct OperationBudget {
    packet_count: u64,
    maximum_wire_bytes: u64,
    delay: Duration,
}

struct PreparedOperation {
    deadline: Deadline,
    query: Bytes,
    delay: Duration,
    summary: Summary,
}

fn prepare_operation<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
) -> std::result::Result<PreparedOperation, Error> {
    let deadline = Deadline::new(request.limits.max_duration);
    let query_name = request.validate()?;
    let query = encode_query(
        &query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
    )
    .map_err(Error::Query)?;
    let budget = operation_budget(request, query.len())?;
    // This complete-operation gate deliberately precedes resolution and probe
    // construction. The authorizer's resolver path independently enforces the
    // declared hostname before every resolver side effect.
    approve_operation(
        authorizer,
        budget.packet_count,
        budget.maximum_wire_bytes,
        &deadline,
        duration_error,
    )?;

    Ok(PreparedOperation {
        deadline,
        query,
        delay: budget.delay,
        summary: Summary {
            server: request.server.to_string(),
            server_port: request.server_port,
            resolved_addresses: Vec::new(),
            query_name,
            query_type: request.query_type,
            transaction_id: request.transaction_id,
            outcome: Outcome::Timeout,
            response: None,
            diagnostics: Vec::new(),
            stats: Stats::default(),
        },
    })
}

fn operation_budget(
    request: &Request,
    query_bytes: usize,
) -> std::result::Result<OperationBudget, Error> {
    let packet_count = u64::from(request.attempts);
    let per_probe_bytes = u64::try_from(query_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(MAX_DNS_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(per_probe_bytes)
            .ok_or(Error::InvalidLimit {
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
        .ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    Ok(OperationBudget {
        packet_count,
        maximum_wire_bytes,
        delay,
    })
}

struct Operation<'a, A, E, C, F> {
    request: &'a Request,
    authorizer: &'a mut A,
    registry: &'a Registry,
    executor: &'a mut E,
    clock: &'a mut C,
    deadline: Deadline,
    query: Bytes,
    delay: Duration,
    summary: Summary,
    evidence_budget: Budget,
    fallback_rank: u8,
    scheduled_delay: Duration,
    attempts_completed: u32,
    retained_undecoded: usize,
    emit: &'a mut F,
}

struct ClassifiedAttempt {
    evidence: AttemptEvidence,
    response: Option<ValidatedResponse>,
}

impl<A, E, C, F> Operation<'_, A, E, C, F>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
    fn execute(mut self) -> std::result::Result<Summary, Error> {
        for attempt in 1..=self.request.attempts {
            if self.execute_attempt(attempt)? {
                break;
            }
        }
        self.deadline.check()?;
        self.summary.stats.elapsed = self
            .summary
            .stats
            .elapsed
            .checked_add(self.scheduled_delay)
            .ok_or(Error::StatisticsOverflow {
                attempt: self.attempts_completed,
            })?;
        Ok(self.summary)
    }

    fn execute_attempt(&mut self, attempt: u32) -> std::result::Result<bool, Error> {
        self.wait_before_attempt(attempt)?;
        let probe = self.prepare_probe(attempt)?;
        let execution = self.execute_probe(&probe)?;
        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let best = select_response(
            &self.deadline,
            self.registry,
            &probe,
            &execution,
            self.request.limits,
            self.request.timeout,
        )?;
        let classified = match best {
            Some(candidate) => self.candidate_evidence(&probe, sent_at, candidate),
            None => ClassifiedAttempt {
                evidence: timeout_evidence(&probe, sent_at),
                response: None,
            },
        };
        let terminal = matches!(
            classified.evidence.status,
            Outcome::Response | Outcome::Truncated
        );
        self.attempts_completed = attempt;
        self.emit_attempt(classified.evidence)?;
        if let Some(response) = classified.response {
            self.emit_response(attempt, response)?;
        }
        self.retain_undecoded(attempt, execution.undecoded)?;
        Ok(terminal)
    }

    fn wait_before_attempt(&mut self, attempt: u32) -> std::result::Result<(), Error> {
        if attempt != 1 {
            self.deadline.check()?;
            self.deadline.start_accounting(self.delay)?;
            self.clock
                .sleep(self.delay)
                .map_err(|source| Error::Clock {
                    attempt,
                    message: source.to_string(),
                })?;
            self.deadline.account(self.delay)?;
            self.scheduled_delay =
                self.scheduled_delay
                    .checked_add(self.delay)
                    .ok_or(Error::DurationLimit {
                        actual: Duration::MAX,
                        limit: self.request.limits.max_duration,
                    })?;
        }
        Ok(())
    }

    fn prepare_probe(&mut self, attempt: u32) -> std::result::Result<Probe, Error> {
        let resolved = resolve_selected(
            self.authorizer,
            &self.request.server,
            self.request.address_family,
            &self.deadline,
            duration_error,
        )?;
        self.summary.server = resolved.declared;
        let addresses = resolved.addresses;
        if addresses.is_empty() {
            return Err(Error::Family {
                family: self.request.address_family.label(),
            });
        }
        for address in &addresses {
            if !self.summary.resolved_addresses.contains(address) {
                self.summary.resolved_addresses.push(*address);
            }
        }
        let address_index = (usize::try_from(attempt).unwrap_or(1) - 1) % addresses.len();
        let server_address = addresses[address_index];
        let source_port = dns_source_port(self.request.source_port, attempt);
        Ok(Probe {
            attempt,
            server_address,
            server_port: self.request.server_port,
            source_port,
            transaction_id: self.request.transaction_id,
            query_name: self.summary.query_name.clone(),
            query_type: self.request.query_type,
            query: self.query.clone(),
        })
    }

    fn execute_probe(&mut self, probe: &Probe) -> std::result::Result<Execution, Error> {
        self.deadline.start_accounting(Duration::ZERO)?;
        let execution_request = Exchange {
            probe: probe.clone(),
            timeout: self.request.timeout,
            max_responses: self.request.limits.max_evidence_frames,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        let execution = self.executor.execute(&execution_request);
        self.deadline.check()?;
        let mut execution = execution.map_err(|source| Error::Execution {
            attempt: probe.attempt,
            source,
        })?;
        if execution.permit != execution_request.permit {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        self.deadline.account(execution.stats.elapsed)?;
        validate_dns_execution(probe, &execution, self.request.limits, self.request.timeout)?;
        self.deadline.check()?;
        self.summary
            .stats
            .checked_add_assign(&execution.stats)
            .ok_or(Error::StatisticsOverflow {
                attempt: probe.attempt,
            })?;
        for diagnostic in execution.diagnostics.drain(..) {
            packetcraftr_core::diagnostic::push_once(&mut self.summary.diagnostics, diagnostic);
        }
        Ok(execution)
    }

    fn candidate_evidence(
        &mut self,
        probe: &Probe,
        sent_at: SystemTime,
        candidate: ResponseCandidate<'_, ResponseClassification>,
    ) -> ClassifiedAttempt {
        let received_at = crate::live_timestamp(&candidate.decoded.frame);
        let latency = Some(candidate.latency);
        let response_frame = retain_evidence(
            &mut self.evidence_budget,
            &candidate.decoded.frame,
            DNS_EVIDENCE_DIAGNOSTICS,
            self.request.limits.max_evidence_frames,
            self.request.limits.max_evidence_bytes,
            &mut self.summary.diagnostics,
        )
        .then(|| candidate.decoded.frame.clone());
        let (status, response_code, reason, response) =
            self.accept_classification(candidate.observation);
        ClassifiedAttempt {
            evidence: AttemptEvidence {
                attempt: probe.attempt,
                server_address: probe.server_address,
                source_port: probe.source_port,
                status,
                sent_at,
                received_at: Some(received_at),
                latency,
                response: response_frame,
                response_code,
                reason,
            },
            response,
        }
    }

    fn accept_classification(
        &mut self,
        classification: ResponseClassification,
    ) -> (Outcome, Option<u16>, String, Option<ValidatedResponse>) {
        match classification {
            ResponseClassification::Response(response) => {
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
                    Outcome::Truncated
                } else {
                    Outcome::Response
                };
                self.summary.outcome = status;
                (status, response_code, reason, Some(response))
            }
            ResponseClassification::NetworkFailure { reason } => {
                let status = Outcome::NetworkFailure;
                update_dns_fallback(&mut self.summary.outcome, &mut self.fallback_rank, status);
                (status, None, reason, None)
            }
            ResponseClassification::DecodeFailure { reason } => {
                let status = Outcome::DecodeFailure;
                update_dns_fallback(&mut self.summary.outcome, &mut self.fallback_rank, status);
                (status, None, reason, None)
            }
            ResponseClassification::Unrelated { reason } => {
                let status = Outcome::Unrelated;
                update_dns_fallback(&mut self.summary.outcome, &mut self.fallback_rank, status);
                (status, None, reason, None)
            }
        }
    }

    fn emit_attempt(&mut self, evidence: AttemptEvidence) -> std::result::Result<(), Error> {
        self.publish(Event::Attempt {
            server: self.summary.server.clone(),
            server_port: self.summary.server_port,
            query_name: self.summary.query_name.clone(),
            query_type: self.summary.query_type,
            evidence,
        })
    }

    fn emit_response(
        &mut self,
        attempt: u32,
        response: ValidatedResponse,
    ) -> std::result::Result<(), Error> {
        let ValidatedResponse {
            transaction_id,
            response_code,
            edns,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            answers,
            authorities,
            additionals,
            rejected_records,
            rejected_record_count,
        } = response;
        for (section, records) in [
            (Section::Answer, answers),
            (Section::Authority, authorities),
            (Section::Additional, additionals),
        ] {
            for record in records {
                self.emit_record(attempt, section, record)?;
            }
        }
        for record in rejected_records {
            self.publish(Event::Rejected {
                attempt,
                server: self.summary.server.clone(),
                server_port: self.summary.server_port,
                query_name: self.summary.query_name.clone(),
                query_type: self.summary.query_type,
                record,
            })?;
        }
        self.summary.response = Some(ResponseSummary {
            transaction_id,
            response_code,
            edns,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            rejected_record_count,
        });
        Ok(())
    }

    fn emit_record(
        &mut self,
        attempt: u32,
        section: Section,
        record: Record,
    ) -> std::result::Result<(), Error> {
        self.publish(Event::Record {
            attempt,
            server: self.summary.server.clone(),
            server_port: self.summary.server_port,
            query_name: self.summary.query_name.clone(),
            query_type: self.summary.query_type,
            section,
            record,
        })
    }

    fn publish(&mut self, event: Event) -> std::result::Result<(), Error> {
        (self.emit)(event).map_err(|source| Error::Output { source })?;
        self.deadline.check()?;
        Ok(())
    }

    fn retain_undecoded(
        &mut self,
        attempt: u32,
        frames: Vec<Frame>,
    ) -> std::result::Result<(), Error> {
        // Correlated response evidence has priority over ambient undecodable
        // frames under the one operation-wide retention budget.
        for frame in frames {
            self.deadline.check()?;
            if self.retained_undecoded >= self.request.limits.max_undecoded {
                push_undecoded_limit_diagnostic(
                    &mut self.summary.diagnostics,
                    DNS_EVIDENCE_DIAGNOSTICS,
                    self.request.limits.max_undecoded,
                );
                break;
            }
            if retain_evidence(
                &mut self.evidence_budget,
                &frame,
                DNS_EVIDENCE_DIAGNOSTICS,
                self.request.limits.max_evidence_frames,
                self.request.limits.max_evidence_bytes,
                &mut self.summary.diagnostics,
            ) {
                self.retained_undecoded += 1;
                self.publish(Event::Undecoded(UndecodedEvidence { attempt, frame }))?;
            }
            self.deadline.check()?;
        }
        Ok(())
    }
}

fn select_response<'a>(
    deadline: &Deadline,
    registry: &Registry,
    probe: &Probe,
    execution: &'a Execution,
    limits: Limits,
    timeout: Duration,
) -> std::result::Result<Option<ResponseCandidate<'a, ResponseClassification>>, Error> {
    let sent_packet = &execution.sent.built().packet;
    let mut best = None;
    for matched in &execution.responses {
        deadline.check()?;
        if response_within_deadline(matched.latency, timeout)
            && let Some(classification) =
                classify_response(registry, probe, sent_packet, &matched.response, limits)
        {
            update_best_candidate(
                &mut best,
                ResponseCandidate {
                    observation: classification,
                    decoded: &matched.response,
                    latency: matched.latency,
                },
                timeout,
                ResponseClassification::rank,
                |_| (),
            );
        }
        deadline.check()?;
    }
    Ok(best)
}

fn timeout_evidence(probe: &Probe, sent_at: SystemTime) -> AttemptEvidence {
    AttemptEvidence {
        attempt: probe.attempt,
        server_address: probe.server_address,
        source_port: probe.source_port,
        status: Outcome::Timeout,
        sent_at,
        received_at: None,
        latency: None,
        response: None,
        response_code: None,
        reason: "no checksum-valid, tuple-correlated DNS response before the deadline".to_owned(),
    }
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

fn dns_rate_delay(rate: Option<u32>) -> std::result::Result<Duration, Error> {
    crate::clock::rate_delay(1, rate).ok_or(Error::InvalidLimit {
        field: "queries_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}

fn update_dns_fallback(outcome: &mut Outcome, rank: &mut u8, candidate: Outcome) {
    let candidate_rank = match candidate {
        Outcome::NetworkFailure => 3,
        Outcome::DecodeFailure => 2,
        Outcome::Unrelated => 1,
        Outcome::Timeout | Outcome::Response | Outcome::Truncated => 0,
    };
    if candidate_rank > *rank {
        *outcome = candidate;
        *rank = candidate_rank;
    }
}

fn duration_error(actual: Duration, limit: Duration) -> Error {
    Error::DurationLimit { actual, limit }
}
