// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS retry orchestration across authorization, execution, and outcomes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::registry::Registry;

use crate::BoundaryError;
use crate::Stats;
use crate::authorization::{
    DnsOperation, Operation as AuthorizedOperation, SocketBudget, WireBudget,
};
use crate::clock::Clock;
use crate::evidence::Budget;
use crate::probe::evidence::{
    ResponseCandidate, UndecodedRetention, response_within_deadline, retain_evidence,
    update_best_candidate,
};
use crate::probe::runner::sink_observer;
use crate::target::{Authorizer, Family, Target, approve_operation, resolve_selected};

use super::error::Error;
use super::evidence::validate_dns_execution;
use super::model::{
    AttemptEvidence, Event, EventContext, Exchange, Execution, Executor, Limits, Outcome, Probe,
    Record, Request, Result, Section, Summary, TcpExchange, Transport, UndecodedEvidence,
    ValidatedResponse,
};
use super::wire::{ResponseClassification, classify_response, decode_tcp_frame, encode_query};
use super::{DNS_EVIDENCE_DIAGNOSTICS, MAX_DNS_PROBE_OVERHEAD};

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
    emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
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

struct OperationBudget {
    packet_count: u64,
    maximum_wire_bytes: u64,
    tcp: Option<SocketBudget>,
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
    if let Some(tcp) = budget.tcp {
        deadline.check()?;
        let approval = authorizer.authorize_operation(AuthorizedOperation::Dns(DnsOperation::new(
            WireBudget::new(budget.packet_count, budget.maximum_wire_bytes),
            tcp,
        )));
        deadline.check()?;
        approval?;
    } else {
        approve_operation(
            authorizer,
            budget.packet_count,
            budget.maximum_wire_bytes,
            &deadline,
            duration_error,
        )?;
    }

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
            fallback_attempted: false,
            accepted_transport: None,
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
    let query_bytes = u64::try_from(query_bytes).unwrap_or(u64::MAX);
    let udp_probe_bytes = query_bytes.saturating_add(MAX_DNS_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(udp_probe_bytes)
            .ok_or(Error::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
    let tcp = if request.tcp_fallback {
        let framed_query_bytes = query_bytes.checked_add(2).ok_or(Error::InvalidLimit {
            field: "socket_bytes",
            value: u64::MAX,
            reason: "DNS-over-TCP framing accounting overflowed".to_owned(),
        })?;
        let application_bytes =
            packet_count
                .checked_mul(framed_query_bytes)
                .ok_or(Error::InvalidLimit {
                    field: "socket_bytes",
                    value: u64::MAX,
                    reason: "DNS-over-TCP byte accounting overflowed".to_owned(),
                })?;
        let max_duration =
            request
                .timeout
                .checked_mul(request.attempts)
                .ok_or(Error::DurationLimit {
                    actual: Duration::MAX,
                    limit: request.limits.max_duration,
                })?;
        Some(SocketBudget::new(
            packet_count,
            packet_count,
            application_bytes,
            max_duration,
        ))
    } else {
        None
    };
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
        tcp,
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

struct ProbeExecution {
    execution: Execution,
    timeout: Duration,
    attempt_deadline: Deadline,
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
        let diagnostic_start = self.summary.diagnostics.len();
        let ProbeExecution {
            execution,
            timeout,
            mut attempt_deadline,
        } = self.execute_probe(&probe)?;
        self.publish_diagnostics_since(diagnostic_start)?;
        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let best = select_response(
            &self.deadline,
            self.registry,
            &probe,
            &execution,
            self.request.limits,
            timeout,
        )?;
        let retention_diagnostic_start = self.summary.diagnostics.len();
        let udp = match best {
            Some(candidate) => self.candidate_evidence(&probe, sent_at, candidate),
            None => ClassifiedAttempt {
                evidence: timeout_evidence(&probe, sent_at),
                response: None,
            },
        };
        self.publish_diagnostics_since(retention_diagnostic_start)?;
        self.attempts_completed = attempt;
        let udp_status = udp.evidence.status;
        self.emit_attempt(udp.evidence)?;
        self.retain_undecoded(attempt, execution.undecoded)?;
        let terminal = match (udp_status, udp.response) {
            (Outcome::Response, Some(response)) => {
                self.accept_response(attempt, Transport::Udp, response)?;
                true
            }
            (Outcome::Truncated, Some(response)) if !self.request.tcp_fallback => {
                self.accept_response(attempt, Transport::Udp, response)?;
                true
            }
            (Outcome::Truncated, Some(_)) => {
                let tcp = self.execute_tcp_fallback(&probe, &mut attempt_deadline)?;
                let tcp_status = tcp.evidence.status;
                self.emit_attempt(tcp.evidence)?;
                if tcp_status == Outcome::Response {
                    let response = tcp.response.ok_or(Error::InvalidEvidence {
                        attempt,
                        message: "successful TCP fallback omitted its validated response"
                            .to_owned(),
                    })?;
                    self.accept_response(attempt, Transport::Tcp, response)?;
                    true
                } else {
                    update_dns_fallback(
                        &mut self.summary.outcome,
                        &mut self.fallback_rank,
                        tcp_status,
                    );
                    false
                }
            }
            (status, None) => {
                update_dns_fallback(&mut self.summary.outcome, &mut self.fallback_rank, status);
                false
            }
            _ => {
                return Err(Error::InvalidEvidence {
                    attempt,
                    message: "DNS classification returned an incoherent response phase".to_owned(),
                });
            }
        };
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
        if self.request.tcp_fallback
            && let IpAddr::V6(address) = server_address
            && address.is_unicast_link_local()
        {
            return Err(Error::TcpLinkLocal { address });
        }
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

    fn execute_probe(&mut self, probe: &Probe) -> std::result::Result<ProbeExecution, Error> {
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
        let _ = attempt_deadline.account(execution.stats.elapsed);
        validate_dns_execution(probe, &execution, self.request.limits, timeout)?;
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
        Ok(ProbeExecution {
            execution,
            timeout,
            attempt_deadline,
        })
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
                transport: Transport::Udp,
                server_address: probe.server_address,
                source_port: Some(probe.source_port),
                status,
                sent_at: Some(sent_at),
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
                (status, response_code, reason, Some(response))
            }
            ResponseClassification::NetworkFailure { reason } => {
                let status = Outcome::NetworkFailure;
                (status, None, reason, None)
            }
            ResponseClassification::DecodeFailure { reason } => {
                let status = Outcome::DecodeFailure;
                (status, None, reason, None)
            }
            ResponseClassification::Unrelated { reason } => {
                let status = Outcome::Unrelated;
                (status, None, reason, None)
            }
        }
    }

    fn execute_tcp_fallback(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> std::result::Result<ClassifiedAttempt, Error> {
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
            max_message_bytes: self.request.limits.max_message_bytes,
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
            .ok_or(Error::StatisticsOverflow {
                attempt: probe.attempt,
            })?;

        if attempt_expired || reported_elapsed > timeout {
            return Ok(tcp_timeout_evidence(
                probe,
                "DNS-over-TCP did not complete within the shared attempt deadline",
            ));
        }
        match result {
            Ok(execution) => self.classify_tcp_response(probe, timeout, execution.response),
            Err(error) if error.is_timeout() => Ok(tcp_failure_evidence(
                probe,
                Outcome::Timeout,
                error.to_string(),
            )),
            Err(error) if error.is_network() => Ok(tcp_failure_evidence(
                probe,
                Outcome::NetworkFailure,
                error.to_string(),
            )),
            Err(error) if error.is_framing() => Ok(tcp_failure_evidence(
                probe,
                Outcome::DecodeFailure,
                error.to_string(),
            )),
            Err(source) if source.is_unsupported() => Err(Error::TcpExecution {
                attempt: probe.attempt,
                source,
            }),
            Err(error) => Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: format!("TCP executor rejected the validated local request: {error}"),
            }),
        }
    }

    fn authorize_tcp_destination(
        &mut self,
        probe: &Probe,
        attempt_deadline: &Deadline,
    ) -> std::result::Result<bool, Error> {
        if attempt_deadline.check().is_err() {
            return Ok(false);
        }
        let target = Target::Address(probe.server_address);
        let resolved = resolve_selected(
            self.authorizer,
            &target,
            Family::Any,
            &self.deadline,
            duration_error,
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

    fn classify_tcp_response(
        &self,
        probe: &Probe,
        timeout: Duration,
        response: packetcraftr_netio::dns_tcp::Response,
    ) -> std::result::Result<ClassifiedAttempt, Error> {
        let expected_written = probe
            .query
            .len()
            .checked_add(2)
            .ok_or(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP query length accounting overflowed".to_owned(),
            })?;
        if response.local_address.port() == 0
            || response.peer_address != SocketAddr::new(probe.server_address, probe.server_port)
            || response.bytes_written != expected_written
            || response.bytes_read != response.frame.len()
            || response.elapsed > timeout
            || response.latency > response.elapsed
        {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "TCP executor returned inconsistent endpoint, byte, or deadline evidence"
                    .to_owned(),
            });
        }
        let (status, response_code, reason, validated) = match decode_tcp_frame(
            &response.frame,
            &probe.query_name,
            probe.query_type,
            probe.transaction_id,
            self.request.limits,
        ) {
            Ok(validated) => (
                Outcome::Response,
                Some(validated.metadata.response_code),
                format!(
                    "validated DNS-over-TCP response with code {}",
                    validated.response_code_name()
                ),
                Some(validated),
            ),
            Err(error) if error.is_unrelated() => {
                (Outcome::Unrelated, None, error.to_string(), None)
            }
            Err(error) => (Outcome::DecodeFailure, None, error.to_string(), None),
        };
        Ok(ClassifiedAttempt {
            evidence: AttemptEvidence {
                attempt: probe.attempt,
                transport: Transport::Tcp,
                server_address: probe.server_address,
                source_port: Some(response.local_address.port()),
                status,
                sent_at: Some(response.sent_at),
                received_at: Some(response.received_at),
                latency: Some(response.latency),
                response: None,
                response_code,
                reason,
            },
            response: validated,
        })
    }

    fn emit_attempt(&mut self, evidence: AttemptEvidence) -> std::result::Result<(), Error> {
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
    ) -> std::result::Result<(), Error> {
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
    ) -> std::result::Result<(), Error> {
        self.publish(Event::Record {
            attempt,
            transport,
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
            |frame| {
                Event::Undecoded(UndecodedEvidence {
                    attempt,
                    transport: Transport::Udp,
                    frame,
                })
            },
            Event::Diagnostic,
            |event| (self.emit)(event, &self.deadline),
            || self.deadline.check().map_err(Into::into),
        )
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
        transport: Transport::Udp,
        server_address: probe.server_address,
        source_port: Some(probe.source_port),
        status: Outcome::Timeout,
        sent_at: Some(sent_at),
        received_at: None,
        latency: None,
        response: None,
        response_code: None,
        reason: "no checksum-valid, tuple-correlated DNS response before the deadline".to_owned(),
    }
}

fn tcp_timeout_evidence(probe: &Probe, reason: &'static str) -> ClassifiedAttempt {
    tcp_failure_evidence(probe, Outcome::Timeout, reason.to_owned())
}

fn tcp_failure_evidence(probe: &Probe, status: Outcome, reason: String) -> ClassifiedAttempt {
    ClassifiedAttempt {
        evidence: AttemptEvidence {
            attempt: probe.attempt,
            transport: Transport::Tcp,
            server_address: probe.server_address,
            source_port: None,
            status,
            sent_at: None,
            received_at: None,
            latency: None,
            response: None,
            response_code: None,
            reason,
        },
        response: None,
    }
}

pub(super) fn dns_source_port(base: u16, attempt: u32) -> u16 {
    crate::probe::ephemeral_source_port(base, u64::from(attempt.saturating_sub(1)))
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
