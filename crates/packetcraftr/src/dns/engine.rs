// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::registry::Registry;

use crate::BoundaryError;
use crate::Stats;
use crate::clock::Clock;
use crate::evidence::{Budget, DiagnosticLog};
use crate::policy::Authorizer;
use crate::policy::{DnsOperation, Operation as AuthorizedOperation, WireBudget};
use crate::probe::Executor;
use crate::probe::evidence::{
    ResponseCandidate, UndecodedRetention, response_within_deadline, update_best_candidate,
};
use crate::probe::runner::sink_observer;
use crate::target::{Family, approve_operation, require_family, resolve_selected};

use super::EVIDENCE_DIAGNOSTICS;
use super::classification::{
    ResponseClassification, candidate_evidence, classify_response, timeout_evidence,
};
use super::error::Error;
use super::evidence::validate_dns_execution;
use super::plan::{OperationBudget, operation_budget};
use super::probe::rotated_source_port;
use super::report::Collector;
use super::{
    AttemptEvidence, Event, EventContext, Exchange, Execution, Limits, Outcome, Probe, Record,
    Report, Request, Section, Summary, TcpExecutor, Transport, TransportMode, UndecodedEvidence,
    ValidatedResponse,
};

mod tcp;

/// Executes bounded DNS retries, repeating declared-name authorization,
/// resolution, and resolved-answer authorization before each attempt. Direct
/// TCP and configured fallback reauthorize the selected numeric address and
/// use only the time left in that attempt.
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
    collector.finish(summary)
}

/// Executes one approved DNS retry sequence and publishes attempts, accepted
/// and rejected records, and retained undecoded evidence as they become final.
/// The callback runs on a runtime-budgeted worker. `max_duration` bounds
/// publisher waiting and live I/O, not arbitrary callback execution. Callback
/// failure prevents later retries; a callback may finish after this function
/// returns and holds one runtime worker permit until then.
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
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    run_observed_with_deadline(
        request,
        authorizer,
        registry,
        executor,
        clock,
        &mut deadline,
        emit,
    )
}

pub(super) fn run_observed_with_deadline<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Exchange> + TcpExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    deadline.check_cancelled()?;
    let mut prepared = PreparedOperation::new(request)?;
    // `Operation::Dns` is deliberately approved before any server resolution:
    // destination authorization follows budget approval for this shape, so
    // admission cannot route through `admit_operation`'s resolve-first order.
    approve_operation(
        authorizer,
        AuthorizedOperation::Dns(prepared.budget),
        deadline,
        &Gates,
    )?;
    prepared.execute(authorizer, registry, executor, clock, deadline, emit)?;
    Ok(prepared.summary)
}

/// Validated query and finite cost, prepared without discovery or traffic.
/// The summary retains confirmed accounting even if execution returns an error.
pub(super) struct PreparedOperation<'a> {
    request: &'a Request,
    query: Bytes,
    pub(super) delay: Duration,
    pub(super) budget: DnsOperation,
    pub(super) summary: Summary,
}

impl<'a> PreparedOperation<'a> {
    pub(super) fn new(request: &'a Request) -> Result<Self, Error> {
        let query_name = request.canonical_name()?;
        let query = super::wire::encode_query(
            &query_name,
            request.query_type,
            request.transaction_id,
            request.recursion_desired,
            request.edns,
        )
        .map_err(Error::Query)?;
        let budget = operation_budget(request, query.len())?;
        let OperationBudget {
            packet_count,
            maximum_wire_bytes,
            tcp,
            delay,
        } = budget;
        Ok(Self {
            request,
            query,
            delay,
            budget: DnsOperation::new(WireBudget::new(packet_count, maximum_wire_bytes), tcp)?,
            summary: Summary {
                server: request.server.to_string(),
                server_port: request.server_port,
                resolved_addresses: Vec::new(),
                query_name,
                query_type: request.query_type,
                transaction_id: request.transaction_id,
                completion: super::Completion::new(Outcome::Timeout, false, None, None)?,
                stats: Stats::default(),
            },
        })
    }

    /// Executes after the caller authorizes this query's cost, either on its own
    /// or within the combined batch. Endpoint authorization still runs per attempt.
    pub(super) fn execute<A, E, C, F>(
        &mut self,
        authorizer: &mut A,
        registry: &Registry,
        executor: &mut E,
        clock: &mut C,
        deadline: &mut Deadline,
        mut emit: F,
    ) -> Result<(), Error>
    where
        A: Authorizer,
        E: Executor<Exchange> + TcpExecutor,
        C: Clock,
        F: FnMut(Event, &Deadline) -> Result<(), Error>,
    {
        deadline.enforce()?;
        let context = Arc::new(EventContext {
            server: Arc::from(self.summary.server.as_str()),
            server_port: self.summary.server_port,
            query_name: Arc::from(self.summary.query_name.as_str()),
            query_type: self.summary.query_type,
        });
        Operation {
            request: self.request,
            authorizer,
            registry,
            executor,
            clock,
            deadline,
            query: self.query.clone(),
            delay: self.delay,
            context,
            summary: &mut self.summary,
            state: DnsState::default(),
            emit: &mut emit,
        }
        .execute()
    }
}

#[derive(Default)]
struct DnsState {
    evidence_budget: Budget,
    diagnostics: DiagnosticLog,
    retained_undecoded: usize,
}

struct Operation<'a, A, E, C, F> {
    request: &'a Request,
    authorizer: &'a mut A,
    registry: &'a Registry,
    executor: &'a mut E,
    clock: &'a mut C,
    deadline: &'a mut Deadline,
    query: Bytes,
    delay: Duration,
    context: Arc<EventContext>,
    summary: &'a mut Summary,
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
    fn execute(mut self) -> Result<(), Error> {
        for attempt in 1..=self.request.attempts {
            if self.execute_attempt(attempt)? {
                break;
            }
        }
        self.deadline.enforce()?;
        self.summary.completion.validate()?;
        Ok(())
    }

    fn execute_attempt(&mut self, attempt: u32) -> Result<bool, Error> {
        self.wait_before_attempt(attempt)?;
        let probe = self.prepare_probe(attempt)?;
        if self.request.transport == TransportMode::Tcp {
            let mut attempt_deadline = self.deadline.for_wait(self.request.timeout)?;
            return self.query_over_tcp(&probe, &mut attempt_deadline);
        }
        let ProbeExecution {
            execution,
            timeout,
            mut attempt_deadline,
        } = self.execute_probe(&probe)?;
        self.publish_new_diagnostics()?;
        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let best = select_response(
            &*self.deadline,
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
        let udp_status = udp.evidence.status;
        self.emit_attempt(udp.evidence)?;
        self.retain_undecoded(attempt, execution.undecoded)?;
        // A validated response is present exactly when the attempt was
        // accepted.
        let terminal = match udp.response {
            None => {
                self.record_failure_outcome(udp_status);
                false
            }
            Some(_)
                if udp_status == Outcome::Truncated
                    && self.request.transport == TransportMode::UdpThenTcp =>
            {
                self.summary.completion.fallback_attempted = true;
                self.query_over_tcp(&probe, &mut attempt_deadline)?
            }
            Some(response) => {
                self.accept_response(attempt, Transport::Udp, response)?;
                true
            }
        };
        Ok(terminal)
    }

    /// Runs a direct query or an admitted continuation under the attempt's
    /// remaining deadline, and reports whether it ended the operation.
    fn query_over_tcp(
        &mut self,
        probe: &Probe,
        attempt_deadline: &mut Deadline,
    ) -> Result<bool, Error> {
        let tcp = self.execute_tcp_query(probe, attempt_deadline)?;
        let tcp_status = tcp.evidence.status;
        self.emit_attempt(tcp.evidence)?;
        if tcp_status != Outcome::Response {
            self.record_failure_outcome(tcp_status);
            return Ok(false);
        }
        let response = tcp.response.ok_or(Error::InvalidEvidence {
            attempt: probe.attempt,
            message: "successful TCP query omitted its validated response".to_owned(),
        })?;
        self.accept_response(probe.attempt, Transport::Tcp, response)?;
        Ok(true)
    }

    /// Keeps the most informative failure seen so far as the operation
    /// outcome. An accepted response is recorded by [`Self::accept_response`]
    /// and ends the operation, so it never competes here.
    fn record_failure_outcome(&mut self, candidate: Outcome) {
        if candidate.retry_rank() > self.summary.completion.outcome.retry_rank() {
            self.summary.completion.outcome = candidate;
        }
    }

    fn wait_before_attempt(&mut self, attempt: u32) -> Result<(), Error> {
        if attempt != 1 {
            self.deadline.enforce()?;
            self.deadline.start_accounting(self.delay)?;
            let slept = self.clock.sleep(self.delay);
            self.deadline.check_cancelled()?;
            slept.map_err(|source| Error::Clock {
                attempt,
                source: Box::new(source),
            })?;
            self.summary.stats.elapsed =
                self.summary
                    .stats
                    .elapsed
                    .checked_add(self.delay)
                    .ok_or(Error::DurationLimit {
                        actual: Duration::MAX,
                        limit: self.request.limits.max_duration,
                    })?;
            self.deadline.account(self.delay)?;
        }
        Ok(())
    }

    fn prepare_probe(&mut self, attempt: u32) -> Result<Probe, Error> {
        self.deadline.enforce()?;
        let resolved = resolve_selected(
            self.authorizer,
            &self.request.server,
            self.request.address_family,
            &*self.deadline,
            &Gates,
        );
        self.deadline.enforce()?;
        let resolved = resolved?;
        self.summary.server = resolved.declared;
        let addresses = resolved.addresses;
        require_family(&addresses, self.request.address_family, &Gates)?;
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
        // address_index is a remainder modulo addresses.len(), which is non-empty
        let server_address = addresses[address_index];
        if self.request.transport != TransportMode::Udp
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
        self.deadline.start_accounting(Duration::ZERO)?;
        let timeout = self.deadline.bounded_timeout(self.request.timeout)?;
        let mut attempt_deadline = Deadline::new(self.request.timeout);
        let execution_request = Exchange {
            probe: probe.clone(),
            timeout,
            limits: self.request.limits,
            permit: crate::evidence::ExecutionPermit::new(),
        };
        self.deadline.enforce()?;
        let execution = self.executor.execute(&execution_request);
        let interrupted = self.deadline.enforce();
        let mut execution = match execution {
            Ok(execution) => execution,
            Err(source) => {
                interrupted?;
                return Err(Error::Execution {
                    attempt: probe.attempt,
                    source,
                });
            }
        };
        if execution.permit != execution_request.permit {
            return Err(Error::InvalidEvidence {
                attempt: probe.attempt,
                message: "executor returned evidence for a different execution permit".to_owned(),
            });
        }
        validate_dns_execution(probe, &execution, self.request.limits, timeout)?;
        // Confirm the receipt before charging it, but retain that traffic even
        // when cancellation or elapsed time stops this question at the boundary.
        self.summary
            .stats
            .checked_add_assign(&execution.stats)
            .map_err(|_| Error::StatisticsOverflow {
                attempt: probe.attempt,
            })?;
        interrupted?;
        self.deadline.account(execution.stats.elapsed)?;
        let _ = attempt_deadline.account(execution.stats.elapsed);
        self.deadline.enforce()?;
        for diagnostic in execution.diagnostics.drain(..) {
            self.state.diagnostics.push_once(diagnostic);
        }
        Ok(ProbeExecution {
            execution,
            timeout,
            attempt_deadline,
        })
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
        self.summary.completion.outcome = if metadata.truncated {
            Outcome::Truncated
        } else {
            Outcome::Response
        };
        self.summary.completion.accepted_transport = Some(transport);
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
        self.summary.completion.response = Some(metadata);
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
        (self.emit)(event, &*self.deadline)?;
        self.deadline.enforce()?;
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
            |event| (self.emit)(event, &*self.deadline),
            || self.deadline.enforce().map_err(Into::into),
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
        self.deadline.enforce()?;
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
        deadline.enforce()?;
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
        deadline.enforce()?;
    }
    Ok(best)
}

pub(super) struct Gates;

impl crate::target::GateErrors for Gates {
    type Error = Error;

    fn duration_limit(&self, actual: Duration, limit: Duration) -> Error {
        duration_error(actual, limit)
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::from(source)
    }

    fn interrupted(&self, source: Interrupted) -> Error {
        Error::from(source)
    }

    fn family(&self, family: Family) -> Error {
        Error::Family {
            family: family.label(),
        }
    }
}

pub(super) fn duration_error(actual: Duration, limit: Duration) -> Error {
    Error::DurationLimit { actual, limit }
}
