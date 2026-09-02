// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dns::tcp::Category as TcpCategory;
use crate::progress::Runtime;
use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::registry::Registry;

use crate::BoundaryError;
use crate::Stats;
use crate::authorization::{DnsOperation, Operation as AuthorizedOperation, WireBudget};
use crate::clock::Clock;
use crate::evidence::{Budget, DiagnosticLog};
use crate::probe::Executor;
use crate::probe::evidence::{
    ResponseCandidate, UndecodedRetention, response_within_deadline, update_best_candidate,
};
use crate::probe::runner::sink_observer;
use crate::target::{Authorizer, Family, Target, approve_operation, resolve_selected};

use super::EVIDENCE_DIAGNOSTICS;
use super::classification::{
    ClassifiedAttempt, ResponseClassification, candidate_evidence, classify_response,
    classify_tcp_response, tcp_failure_evidence, tcp_timeout_evidence, timeout_evidence,
};
use super::error::Error;
use super::evidence::validate_dns_execution;
use super::model::{
    AttemptEvidence, Event, EventContext, Exchange, Execution, Limits, Outcome, Probe, Record,
    Report, Request, Section, Summary, TcpExchange, TcpExecutor, Transport, UndecodedEvidence,
    ValidatedResponse,
};
use super::plan::{OperationBudget, operation_budget};
use super::probe::rotated_source_port;

/// Executes bounded DNS retries, repeating declared-name authorization,
/// resolution, and resolved-answer authorization before each UDP probe. A
/// configured TCP fallback reauthorizes the selected numeric address and uses
/// only the time left in that attempt.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
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
/// The callback runs on a process-budgeted worker. `max_duration` bounds
/// publisher waiting and live I/O, not arbitrary callback execution. Callback
/// failure prevents later retries; a callback may finish after this function
/// returns and holds one process-wide worker permit until then.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
        runtime,
        emit,
        |error| duration_error(error.actual, error.limit),
        |source| Error::Output { source },
    )?;
    run_observed(request, authorizer, registry, executor, clock, observe)
}

fn run_observed<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
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
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
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
        state: DnsState::default(),
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

    pub(super) fn finish(self, summary: Summary) -> Report {
        let response = summary.response.map(|response| ValidatedResponse {
            metadata: response,
            answers: self.answers,
            authorities: self.authorities,
            additionals: self.additionals,
            rejected_records: self.rejected,
        });
        Report {
            server: summary.server,
            server_port: summary.server_port,
            resolved_addresses: summary.resolved_addresses,
            query_name: summary.query_name,
            query_type: summary.query_type,
            transaction_id: summary.transaction_id,
            outcome: summary.outcome,
            fallback_attempted: summary.fallback_attempted,
            accepted_transport: summary.accepted_transport,
            response,
            attempts: self.attempts,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats: summary.stats,
        }
    }
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
) -> Result<PreparedOperation, Error> {
    let query_name = request.canonical_name()?;
    let query = super::wire::encode_query(
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
    let OperationBudget {
        packet_count,
        maximum_wire_bytes,
        tcp,
        delay,
    } = budget;
    approve_operation(
        authorizer,
        AuthorizedOperation::Dns(DnsOperation::new(
            WireBudget::new(packet_count, maximum_wire_bytes),
            tcp,
        )),
        &deadline,
        &Gates,
    )?;

    Ok(PreparedOperation {
        deadline,
        query,
        delay,
        summary: Summary {
            server: request.server.to_string(),
            server_port: request.server_port,
            resolved_addresses: Vec::new(),
            query_name,
            query_type: request.query_type,
            transaction_id: request.transaction_id,
            outcome: Outcome::Timeout,
            fallback_attempted: false,
            accepted_transport: None,
            response: None,
            stats: Stats::default(),
        },
    })
}

/// Everything one running DNS operation accumulates, kept apart from the
/// [`Summary`] it publishes.
#[derive(Default)]
struct DnsState {
    evidence_budget: Budget,
    diagnostics: DiagnosticLog,
    scheduled_delay: Duration,
    attempts_completed: u32,
    retained_undecoded: usize,
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
    state: DnsState,
    emit: &'a mut F,
}

struct ProbeExecution {
    execution: Execution,
    timeout: Duration,
    attempt_deadline: Deadline,
}

impl<A, E, C, F> Operation<'_, A, E, C, F>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn execute(mut self) -> Result<Summary, Error> {
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
            .checked_add(self.state.scheduled_delay)
            .ok_or(Error::StatisticsOverflow {
                attempt: self.state.attempts_completed,
            })?;
        Ok(self.summary)
    }

    fn execute_attempt(&mut self, attempt: u32) -> Result<bool, Error> {
        self.wait_before_attempt(attempt)?;
        let probe = self.prepare_probe(attempt)?;
        let ProbeExecution {
            execution,
            timeout,
            mut attempt_deadline,
        } = self.execute_probe(&probe)?;
        self.publish_new_diagnostics()?;
        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let best = select_response(
            &self.deadline,
            self.registry,
            &probe,
            &execution,
            self.request.limits,
            timeout,
        )?;
        let udp = match best {
            Some(candidate) => candidate_evidence(
                &probe,
                sent_at,
                candidate,
                self.request.limits,
                &mut self.state.evidence_budget,
                &mut self.state.diagnostics,
            ),
            None => timeout_evidence(&probe, sent_at),
        };
        self.publish_new_diagnostics()?;
        self.state.attempts_completed = attempt;
        let udp_status = udp.evidence.status;
        self.emit_attempt(udp.evidence)?;
        self.retain_undecoded(attempt, execution.undecoded)?;
        // A validated response is present exactly when the attempt was
        // accepted, so this match is total: there is no shape for "timed out
        // and yet produced a response".
        let terminal = match udp.response {
            None => {
                self.record_failure_outcome(udp_status);
                false
            }
            // A truncated response continues over TCP when — and only when —
            // a continuation was configured.
            Some(_) if udp_status == Outcome::Truncated && self.request.tcp_fallback => {
                self.continue_over_tcp(&probe, &mut attempt_deadline)?
            }
            Some(response) => {
                self.accept_response(attempt, Transport::Udp, response)?;
                true
            }
        };
        Ok(terminal)
    }

    /// Runs the one DNS-over-TCP continuation a validated truncated response
    /// permits, and reports whether it ended the operation.
    fn continue_over_tcp(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> Result<bool, Error> {
        let tcp = self.execute_tcp_fallback(probe, attempt_deadline)?;
        let tcp_status = tcp.evidence.status;
        self.emit_attempt(tcp.evidence)?;
        if tcp_status != Outcome::Response {
            self.record_failure_outcome(tcp_status);
            return Ok(false);
        }
        let response = tcp.response.ok_or(Error::InvalidEvidence {
            attempt: probe.attempt,
            message: "successful TCP fallback omitted its validated response".to_owned(),
        })?;
        self.accept_response(probe.attempt, Transport::Tcp, response)?;
        Ok(true)
    }

    /// Keeps the most informative failure seen so far as the operation
    /// outcome. An accepted response is recorded by [`Self::accept_response`]
    /// and ends the operation, so it never competes here.
    fn record_failure_outcome(&mut self, candidate: Outcome) {
        if candidate.retry_rank() > self.summary.outcome.retry_rank() {
            self.summary.outcome = candidate;
        }
    }

    fn wait_before_attempt(&mut self, attempt: u32) -> Result<(), Error> {
        if attempt != 1 {
            self.deadline.check()?;
            self.deadline.start_accounting(self.delay)?;
            self.clock
                .sleep(self.delay)
                .map_err(|source| Error::Clock {
                    attempt,
                    source: Box::new(source),
                })?;
            self.deadline.account(self.delay)?;
            self.state.scheduled_delay =
                self.state
                    .scheduled_delay
                    .checked_add(self.delay)
                    .ok_or(Error::DurationLimit {
                        actual: Duration::MAX,
                        limit: self.request.limits.max_duration,
                    })?;
        }
        Ok(())
    }

    fn prepare_probe(&mut self, attempt: u32) -> Result<Probe, Error> {
        let resolved = resolve_selected(
            self.authorizer,
            &self.request.server,
            self.request.address_family,
            &self.deadline,
            &Gates,
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
        if self.request.tcp_fallback
            && let IpAddr::V6(address) = server_address
            && address.is_unicast_link_local()
        {
            return Err(Error::TcpLinkLocal { address });
        }
        Ok(Probe {
            attempt,
            server_address,
            server_port: self.request.server_port,
            source_port: rotated_source_port(self.request.source_port, attempt),
            transaction_id: self.request.transaction_id,
            query_name: self.summary.query_name.clone(),
            query_type: self.request.query_type,
            query: self.query.clone(),
        })
    }

    fn execute_probe(&mut self, probe: &Probe) -> Result<ProbeExecution, Error> {
        let timeout = self.request.timeout.min(self.deadline.remaining()?);
        if timeout.is_zero() {
            return Err(Error::DurationLimit {
                actual: self.request.limits.max_duration,
                limit: self.request.limits.max_duration,
            });
        }
        self.deadline.start_accounting(Duration::ZERO)?;
        let mut attempt_deadline = Deadline::new(self.request.timeout);
        let execution_request = Exchange {
            probe: probe.clone(),
            timeout,
            limits: self.request.limits,
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
        let _ = attempt_deadline.account(execution.stats.elapsed);
        validate_dns_execution(probe, &execution, self.request.limits, timeout)?;
        self.deadline.check()?;
        self.summary
            .stats
            .checked_add_assign(&execution.stats)
            .map_err(|_| Error::StatisticsOverflow {
                attempt: probe.attempt,
            })?;
        for diagnostic in execution.diagnostics.drain(..) {
            self.state.diagnostics.push_once(diagnostic);
        }
        Ok(ProbeExecution {
            execution,
            timeout,
            attempt_deadline,
        })
    }

    fn execute_tcp_fallback(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> Result<ClassifiedAttempt, Error> {
        self.summary.fallback_attempted = true;
        if !self.authorize_tcp_destination(probe, attempt_deadline)? {
            return Ok(tcp_timeout_evidence(
                probe,
                "the shared UDP/TCP attempt deadline expired before connection",
            ));
        }
        let mut exchange = TcpExchange {
            attempt: probe.attempt,
            endpoint: SocketAddr::new(probe.server_address, probe.server_port),
            query: probe.query.clone(),
            timeout: Duration::ZERO,
            max_message_bytes: self.request.limits.message.max_message_bytes,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        self.deadline.start_accounting(Duration::ZERO)?;
        if attempt_deadline.start_accounting(Duration::ZERO).is_err() {
            return Ok(tcp_timeout_evidence(
                probe,
                "the shared UDP/TCP attempt deadline expired before connection",
            ));
        }
        let timeout = attempt_deadline
            .remaining()
            .map_err(|_| Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "shared DNS attempt deadline regressed after accounting".to_owned(),
            })?
            .min(self.deadline.remaining()?);
        if timeout.is_zero() {
            return Ok(tcp_timeout_evidence(
                probe,
                "the shared UDP/TCP attempt deadline expired before connection",
            ));
        }
        exchange.timeout = timeout;
        let boundary_started = Instant::now();
        let result = self.executor.execute_tcp(&exchange);
        let boundary_elapsed = boundary_started.elapsed();
        if let Ok(execution) = &result
            && execution.permit != exchange.permit
        {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP executor returned evidence for a different execution permit"
                    .to_owned(),
            });
        }
        let reported_elapsed = result
            .as_ref()
            .map_or(boundary_elapsed, |execution| execution.response.elapsed);
        self.deadline.account(reported_elapsed)?;
        let attempt_expired = attempt_deadline.account(reported_elapsed).is_err();

        let mut tcp_stats = Stats {
            elapsed: reported_elapsed,
            ..Stats::default()
        };
        let framed_query_bytes =
            probe
                .query
                .len()
                .checked_add(2)
                .ok_or(Error::InvalidEvidence {
                    attempt: probe.attempt,
                    message: "TCP query length accounting overflowed".to_owned(),
                })?;
        let bytes_written = match &result {
            Ok(execution) => execution.response.bytes_written,
            Err(error) => error.query_bytes_written(framed_query_bytes),
        };
        if bytes_written > framed_query_bytes {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP executor reported more query bytes than were authorized".to_owned(),
            });
        }
        tcp_stats.bytes = u64::try_from(bytes_written).unwrap_or(u64::MAX);
        self.summary
            .stats
            .checked_add_assign(&tcp_stats)
            .map_err(|_| Error::StatisticsOverflow {
                attempt: probe.attempt,
            })?;

        if attempt_expired || reported_elapsed > timeout {
            return Ok(tcp_timeout_evidence(
                probe,
                "DNS-over-TCP did not complete within the shared attempt deadline",
            ));
        }
        let error = match result {
            Ok(execution) => {
                return classify_tcp_response(
                    probe,
                    timeout,
                    execution.response,
                    self.request.limits.message,
                );
            }
            Err(error) => error,
        };
        match error.category() {
            TcpCategory::Timeout => Ok(tcp_failure_evidence(
                probe,
                Outcome::Timeout,
                error.to_string(),
            )),
            TcpCategory::Network => Ok(tcp_failure_evidence(
                probe,
                Outcome::NetworkFailure,
                error.to_string(),
            )),
            TcpCategory::Framing => Ok(tcp_failure_evidence(
                probe,
                Outcome::DecodeFailure,
                error.to_string(),
            )),
            TcpCategory::Unsupported => Err(Error::TcpExecution {
                attempt: probe.attempt,
                source: error,
            }),
            // `Request` — and any class added later — fails closed here: a
            // request this workflow built itself cannot be rejected by the
            // executor, so it is never a retryable per-attempt outcome.
            _ => Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: format!("TCP executor rejected the validated local request: {error}"),
            }),
        }
    }

    fn authorize_tcp_destination(
        &mut self,
        probe: &Probe,
        attempt_deadline: &Deadline,
    ) -> Result<bool, Error> {
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let target = Target::Address(probe.server_address);
        let resolved = resolve_selected(
            self.authorizer,
            &target,
            Family::Any,
            &self.deadline,
            &Gates,
        );
        self.deadline.check()?;
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let resolved = resolved?;
        if resolved.addresses.as_slice() != [probe.server_address] {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: format!(
                    "TCP destination reauthorization did not preserve selected server {}",
                    probe.server_address
                ),
            });
        }
        Ok(true)
    }

    fn emit_attempt(&mut self, evidence: AttemptEvidence) -> Result<(), Error> {
        self.publish(Event::Attempt {
            context: Arc::clone(&self.context),
            evidence,
        })
    }

    fn accept_response(
        &mut self,
        attempt: u32,
        transport: Transport,
        response: ValidatedResponse,
    ) -> Result<(), Error> {
        let ValidatedResponse {
            metadata,
            answers,
            authorities,
            additionals,
            rejected_records,
        } = response;
        self.summary.outcome = if metadata.truncated {
            Outcome::Truncated
        } else {
            Outcome::Response
        };
        self.summary.accepted_transport = Some(transport);
        for (section, records) in [
            (Section::Answer, answers),
            (Section::Authority, authorities),
            (Section::Additional, additionals),
        ] {
            for record in records {
                self.emit_record(attempt, transport, section, record)?;
            }
        }
        for record in rejected_records {
            self.publish(Event::Rejected {
                attempt,
                transport,
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
        transport: Transport,
        section: Section,
        record: Record,
    ) -> Result<(), Error> {
        self.publish(Event::Record {
            attempt,
            transport,
            context: Arc::clone(&self.context),
            section,
            record,
        })
    }

    fn publish(&mut self, event: Event) -> Result<(), Error> {
        (self.emit)(event, &self.deadline)?;
        self.deadline.check()?;
        Ok(())
    }

    fn retain_undecoded(&mut self, attempt: u32, frames: Vec<Frame>) -> Result<(), Error> {
        let mut retention = UndecodedRetention::new(
            &mut self.state.retained_undecoded,
            self.request.limits.max_undecoded,
            &mut self.state.evidence_budget,
            EVIDENCE_DIAGNOSTICS,
            self.request.limits.max_evidence_frames,
            self.request.limits.max_evidence_bytes,
            &mut self.state.diagnostics,
        );
        retention.retain(
            frames,
            |frame| Event::Undecoded(UndecodedEvidence { attempt, frame }),
            Event::Diagnostic,
            |event| (self.emit)(event, &self.deadline),
            || self.deadline.check().map_err(Into::into),
        )
    }

    fn publish_new_diagnostics(&mut self) -> Result<(), Error> {
        let Self {
            state,
            emit,
            deadline,
            ..
        } = self;
        state
            .diagnostics
            .publish_new(|diagnostic| emit(Event::Diagnostic(diagnostic), deadline))?;
        self.deadline.check()?;
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
) -> Result<Option<ResponseCandidate<'a, ResponseClassification>>, Error> {
    let sent_packet = &execution.sent.built().packet;
    let mut best = None;
    for matched in &execution.responses {
        deadline.check()?;
        if response_within_deadline(matched.latency, timeout)
            && let Some(classification) = classify_response(
                registry,
                probe,
                sent_packet,
                &matched.response,
                limits.message,
            )
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

/// The DNS workflow's names for the shared policy-gate failures.
struct Gates;

impl crate::target::GateErrors for Gates {
    type Error = Error;

    fn duration_limit(&self, actual: Duration, limit: Duration) -> Error {
        duration_error(actual, limit)
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::from(source)
    }
}

fn duration_error(actual: Duration, limit: Duration) -> Error {
    Error::DurationLimit { actual, limit }
}
