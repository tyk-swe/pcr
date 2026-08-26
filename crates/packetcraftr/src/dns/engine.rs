// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::sync::Arc;
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
    ResponseCandidate, UndecodedRetention, response_within_deadline, retain_evidence,
    update_best_candidate,
};
use crate::target::{Authorizer, approve_operation, resolve_selected};

use super::error::Error;
use super::evidence::validate_dns_execution;
use super::model::{
    AttemptEvidence, Event, EventContext, Exchange, Execution, Executor, Limits, Outcome, Probe,
    Record, Request, Result, Section, Summary, UndecodedEvidence, ValidatedResponse,
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
    let summary = run_observed(
        request,
        authorizer,
        registry,
        executor,
        clock,
        |event, _| {
            collector.observe(event);
            Ok(())
        },
    )?;
    Ok(collector.finish(summary))
}

/// Executes one approved DNS retry sequence and publishes attempts, accepted
/// and rejected records, and retained undecoded evidence as they become final.
/// The callback runs on a bounded worker and cannot extend live I/O beyond
/// `max_duration`. Callback failure prevents later retries; a worker that
/// outlives the deadline may finish after this function returns and must own
/// its state.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError> + Send + 'static,
{
    let sink =
        packetcraftr_core::progress::Sink::new(emit).map_err(|source| Error::Output { source })?;
    run_observed(
        request,
        authorizer,
        registry,
        executor,
        clock,
        move |event, deadline| match sink.emit(event, deadline) {
            Ok(()) => Ok(()),
            Err(packetcraftr_core::progress::EmitError::Deadline(error)) => {
                Err(duration_error(error.actual, error.limit))
            }
            Err(packetcraftr_core::progress::EmitError::Output(source)) => {
                Err(Error::Output { source })
            }
        },
    )
}

fn run_observed<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
{
    run_observed_with_deadline(
        request,
        authorizer,
        registry,
        executor,
        clock,
        Deadline::new(request.limits.max_duration),
        emit,
    )
}

pub(super) fn run_observed_with_deadline<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: Deadline,
    mut emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
{
    let PreparedOperation {
        deadline,
        query,
        delay,
        summary,
    } = prepare_operation(request, authorizer, deadline)?;
    let context = Arc::new(EventContext {
        server: Arc::from(summary.server.as_str()),
        server_port: summary.server_port,
        query_name: Arc::from(summary.query_name.as_str()),
        query_type: summary.query_type,
    });
    Operation {
        request,
        authorizer,
        registry,
        executor,
        clock,
        deadline,
        query,
        delay,
        context,
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
pub(super) struct Collector {
    attempts: Vec<AttemptEvidence>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    rejected: Vec<super::model::RejectedRecord>,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
}

impl Collector {
    pub(super) fn observe(&mut self, event: Event) {
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
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    pub(super) fn finish(mut self, summary: Summary) -> Result {
        let response = summary.response.map(|response| ValidatedResponse {
            metadata: response,
            answers: self.answers,
            authorities: self.authorities,
            additionals: self.additionals,
            rejected_records: self.rejected,
        });
        self.diagnostics.extend(summary.diagnostics);
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
            diagnostics: self.diagnostics,
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
    deadline: Deadline,
) -> std::result::Result<PreparedOperation, Error> {
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
    context: Arc<EventContext>,
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
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
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
        self.summary.diagnostics.clear();
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
        let diagnostic_start = self.summary.diagnostics.len();
        let classified = match best {
            Some(candidate) => self.candidate_evidence(&probe, sent_at, candidate),
            None => ClassifiedAttempt {
                evidence: timeout_evidence(&probe, sent_at),
                response: None,
            },
        };
        self.publish_diagnostics_since(diagnostic_start)?;
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
        let address_index = usize::try_from(attempt)
            .unwrap_or(1)
            .saturating_sub(1)
            .checked_rem(addresses.len())
            .unwrap_or(0);
        #[expect(
            clippy::indexing_slicing,
            reason = "address_index is a remainder modulo addresses.len(), which is non-empty"
        )]
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
            self.record_diagnostic(diagnostic)?;
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
                let truncated = response.metadata.truncated;
                let response_code = Some(response.metadata.response_code);
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
            context: Arc::clone(&self.context),
            evidence,
        })
    }

    fn emit_response(
        &mut self,
        attempt: u32,
        response: ValidatedResponse,
    ) -> std::result::Result<(), Error> {
        let ValidatedResponse {
            metadata,
            answers,
            authorities,
            additionals,
            rejected_records,
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
                context: Arc::clone(&self.context),
                record,
            })?;
        }
        self.summary.response = Some(metadata);
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
            context: Arc::clone(&self.context),
            section,
            record,
        })
    }

    fn publish(&mut self, event: Event) -> std::result::Result<(), Error> {
        (self.emit)(event, &self.deadline)?;
        self.deadline.check()?;
        Ok(())
    }

    fn retain_undecoded(
        &mut self,
        attempt: u32,
        frames: Vec<Frame>,
    ) -> std::result::Result<(), Error> {
        let mut retention = UndecodedRetention::new(
            &mut self.retained_undecoded,
            self.request.limits.max_undecoded,
            &mut self.evidence_budget,
            DNS_EVIDENCE_DIAGNOSTICS,
            self.request.limits.max_evidence_frames,
            self.request.limits.max_evidence_bytes,
            &mut self.summary.diagnostics,
        );
        retention.retain(
            frames,
            |frame| Event::Undecoded(UndecodedEvidence { attempt, frame }),
            Event::Diagnostic,
            |event| (self.emit)(event, &self.deadline),
            || self.deadline.check().map_err(Into::into),
        )
    }

    fn record_diagnostic(
        &mut self,
        diagnostic: packetcraftr_core::diagnostic::Diagnostic,
    ) -> std::result::Result<(), Error> {
        let start = self.summary.diagnostics.len();
        packetcraftr_core::diagnostic::push_once(&mut self.summary.diagnostics, diagnostic);
        self.publish_diagnostics_since(start)
    }

    fn publish_diagnostics_since(&mut self, start: usize) -> std::result::Result<(), Error> {
        let diagnostics = self
            .summary
            .diagnostics
            .get(start..)
            .unwrap_or_default()
            .to_vec();
        for diagnostic in diagnostics {
            self.publish(Event::Diagnostic(diagnostic))?;
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
            u32::from(u16::MAX)
                .saturating_sub(u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE))
                .saturating_add(1),
        )
    } else {
        (
            1,
            u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE).saturating_sub(1),
        )
    };
    let offset = attempt.saturating_sub(1).checked_rem(width).unwrap_or(0);
    let rotated = u32::from(base)
        .saturating_sub(range_start)
        .saturating_add(offset)
        .checked_rem(width)
        .unwrap_or(0);
    range_start.saturating_add(rotated) as u16
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
