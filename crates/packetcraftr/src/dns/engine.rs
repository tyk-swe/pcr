// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::deadline::DeadlineExt as _;
use crate::execution::Context;
use crate::execution::evidence::{
    EvidenceSink, EvidenceState, ResponseCandidate, ResponseSelector,
};
use crate::execution::{ExchangeExecutor, Executor, publisher};
use crate::policy::Authorizer;
use crate::policy::{DnsOperation, Operation, WireLimits};
use crate::providers::Providers;
use crate::target::ResolveTarget;
use crate::target::{FamilyGate, approve_operation, resolve_selected};
use crate::{Client, Sink, Stats, StatsOverflow};
use packetcraftr_core::error::BoundaryError;

use super::EVIDENCE_DIAGNOSTICS;
use super::classification::{
    ResponseClassification, candidate_evidence, classify_response, timeout_evidence,
};
use super::error::{Error, EvidenceFault};
use super::evidence::validate_dns_execution;
use super::executor::{Exchange, ExchangeEvidence, TcpQuerier};
use super::plan::{OperationLimits, operation_limits};
use super::probe::{Probe, rotated_source_port};
use super::{
    AttemptEvidence, Event, EventContext, Limits, Outcome, Record, Report, Request, Section,
    Transport, TransportMode, UndecodedEvidence, ValidatedResponse, batch,
};

mod tcp;

impl<P: Providers, K: Clock> Client<P, K> {
    /// Runs one bounded DNS query and publishes attempts, accepted and
    /// rejected records, and retained undecoded evidence as each becomes
    /// final.
    ///
    /// The query's worst-case traffic is authorized before any resolution;
    /// declared-name authorization, resolution, and resolved-answer
    /// authorization then repeat before each attempt. Direct TCP and a
    /// configured fallback reauthorize the selected numeric address, use only
    /// the time left in that attempt, and query over the client's TCP
    /// provider. `sink` runs on a one-event worker admitted by the client's
    /// [`Runtime`](crate::runtime::Runtime); `limits.max_duration` bounds
    /// waiting for it and live I/O, not the sink itself. A sink failure
    /// prevents later retries, and a sink may finish after this method
    /// returns while it holds one of the runtime's worker permits.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the policy refusal, the executor or
    /// evidence failure, cancellation, the exhausted duration limit, or the
    /// sink's failure.
    pub fn dns<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let mut deadline = self.deadline(request.limits.max_duration);
        let publish = publisher(&self.runtime, sink, Error::from, |source| Error::Output {
            source,
        })?;
        run(
            &request,
            &mut self.admission(),
            &self.registry,
            &mut ExchangeExecutor::new(self, send_options(&request), request.collection.clone()),
            &mut self.clock.clone(),
            &mut deadline,
            publish,
        )
    }

    /// Runs a bounded batch of DNS questions in input order under one
    /// deadline, the shortest `limits.max_duration` among them, and publishes
    /// each question's events tagged with its index.
    ///
    /// The combined worst-case traffic of every question is authorized
    /// before any resolution. Cancellation or deadline exhaustion leaves the
    /// remaining questions [`Unattempted`](batch::QuestionStatus::Unattempted);
    /// other question failures are [`Failed`](batch::QuestionStatus::Failed)
    /// and the batch continues. A sink failure stops the batch.
    ///
    /// # Errors
    ///
    /// Returns an invalid batch, the policy refusal of the combined traffic,
    /// or the sink's failure; question failures are reported in the returned
    /// [`batch::Report`].
    pub fn dns_batch<S>(&self, request: batch::Request, sink: S) -> Result<batch::Report, Error>
    where
        S: Sink<batch::Event, Ack = ()>,
    {
        let mut deadline = self.deadline(request.max_duration()?);
        let publish = publisher(&self.runtime, sink, Error::from, |source| Error::Output {
            source,
        })?;
        let first = &request.questions[0];
        batch::run(
            &request,
            &mut self.admission(),
            &self.registry,
            &mut ExchangeExecutor::new(self, send_options(first), first.collection.clone()),
            &mut self.clock.clone(),
            &mut deadline,
            publish,
        )
    }
}

/// The send settings every DNS exchange runs under: the request's route,
/// with each attempt's destination set by the attempt itself.
fn send_options(request: &Request) -> crate::send::Options {
    crate::send::Options {
        plan: request.route.clone(),
        ..crate::send::Options::default()
    }
}

/// Executes bounded DNS retries, repeating declared-name authorization,
/// resolution, and resolved-answer authorization before each attempt. Direct
/// TCP and configured fallback reauthorize the selected numeric address and
/// use only the time left in that attempt.
pub(super) fn run<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    emit: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    deadline.check_cancelled()?;
    let mut prepared = PreparedOperation::new(request)?;
    // `Operation::Dns` is deliberately approved before any server resolution:
    // destination authorization follows limits approval for this shape, so
    // admission cannot route through `admit_operation`'s resolve-first order.
    approve_operation(
        authorizer,
        Operation::Dns(prepared.limits),
        deadline,
        &Attempts,
    )?;
    prepared.execute(authorizer, registry, executor, clock, deadline, emit)?;
    Ok(prepared.report)
}

/// Validated query and finite cost, prepared without discovery or traffic.
/// The report retains confirmed accounting even if execution returns an error.
pub(super) struct PreparedOperation<'a> {
    request: &'a Request,
    query: Bytes,
    pub(super) delay: Duration,
    pub(super) limits: DnsOperation,
    pub(super) report: Report,
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
        let limits = operation_limits(request, query.len())?;
        let OperationLimits {
            packet_count,
            maximum_wire_bytes,
            tcp,
            delay,
        } = limits;
        Ok(Self {
            request,
            query,
            delay,
            limits: DnsOperation::new(WireLimits::new(packet_count, maximum_wire_bytes), tcp)?,
            report: Report {
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
        A: Authorizer + ResolveTarget,
        E: Executor<Exchange> + TcpQuerier,
        C: Clock,
        F: FnMut(Event, &Deadline) -> Result<(), Error>,
    {
        deadline.enforce()?;
        let context = Arc::new(EventContext {
            server: Arc::from(self.report.server.as_str()),
            server_port: self.report.server_port,
            query_name: Arc::from(self.report.query_name.as_str()),
            query_type: self.report.query_type,
        });
        Retries {
            request: self.request,
            authorizer,
            registry,
            executor,
            execution: Context::new(deadline, clock, Attempts),
            query: self.query.clone(),
            delay: self.delay,
            context,
            report: &mut self.report,
            evidence: EvidenceState::new(self.request.limits.evidence(), EVIDENCE_DIAGNOSTICS),
            emit: &mut emit,
        }
        .execute()
    }
}

/// The retry sequence of one query: every attempt, its fallback, and the
/// events they publish.
struct Retries<'a, A, E, C, F> {
    request: &'a Request,
    authorizer: &'a mut A,
    registry: &'a Registry,
    executor: &'a mut E,
    /// Owns the operation deadline, retry pacing, and the UDP execution step.
    /// Its statistics become the report's when the operation ends, however
    /// it ends.
    execution: Context<'a, C, Attempts>,
    query: Bytes,
    delay: Duration,
    context: Arc<EventContext>,
    report: &'a mut Report,
    /// Operation-wide evidence retention and diagnostics, shared by every
    /// attempt.
    evidence: EvidenceState,
    emit: &'a mut F,
}

struct ProbeAttempt {
    execution: ExchangeEvidence,
    timeout: Duration,
    attempt_deadline: Deadline,
}

impl<A, E, C, F> Retries<'_, A, E, C, F>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn execute(mut self) -> Result<(), Error> {
        let result = self.execute_attempts();
        self.report.stats = self.execution.into_stats();
        result
    }

    fn execute_attempts(&mut self) -> Result<(), Error> {
        let mut last_attempt = 1;
        for attempt in 1..=self.request.attempts {
            last_attempt = attempt;
            if self.execute_attempt(attempt)? {
                break;
            }
        }
        self.execution.enforce(last_attempt)?;
        self.report.completion.validate()?;
        Ok(())
    }

    fn execute_attempt(&mut self, attempt: u32) -> Result<bool, Error> {
        self.wait_before_attempt(attempt)?;
        let probe = self.prepare_probe(attempt)?;
        if self.request.transport == TransportMode::Tcp {
            let mut attempt_deadline = self.execution.deadline().for_wait(self.request.timeout)?;
            return self.query_over_tcp(&probe, &mut attempt_deadline);
        }
        let ProbeAttempt {
            mut execution,
            timeout,
            mut attempt_deadline,
        } = self.execute_probe(&probe)?;
        self.record_diagnostics(attempt, execution.diagnostics.drain(..))?;
        let sent_at = execution.sent.timing().freshness_marker().wall_clock();
        let best = select_response(
            self.registry,
            &probe,
            &mut execution,
            self.request.limits,
            timeout,
            || self.execution.enforce(attempt),
        )?;
        let udp = match best {
            Some(candidate) => candidate_evidence(&probe, sent_at, candidate, &mut self.evidence),
            None => timeout_evidence(&probe, sent_at),
        };
        // Publishes what retaining the response raised.
        self.record_diagnostics(attempt, [])?;
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
                self.report.completion.fallback_attempted = true;
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
            fault: EvidenceFault::TcpResponseMissing,
        })?;
        self.accept_response(probe.attempt, Transport::Tcp, response)?;
        Ok(true)
    }

    /// Keeps the most informative failure seen so far as the operation
    /// outcome. An accepted response is recorded by [`Self::accept_response`]
    /// and ends the operation, so it never competes here.
    fn record_failure_outcome(&mut self, candidate: Outcome) {
        if candidate.retry_rank() > self.report.completion.outcome.retry_rank() {
            self.report.completion.outcome = candidate;
        }
    }

    fn wait_before_attempt(&mut self, attempt: u32) -> Result<(), Error> {
        if attempt == 1 {
            return Ok(());
        }
        self.execution.pace(attempt, self.delay)
    }

    fn prepare_probe(&mut self, attempt: u32) -> Result<Probe, Error> {
        self.execution.enforce(attempt)?;
        let resolved = resolve_selected(
            self.authorizer,
            &self.request.server,
            self.request.address_family,
            self.execution.deadline(),
            &Attempts,
        );
        self.execution.enforce(attempt)?;
        let resolved = resolved?;
        self.report.server = resolved.declared;
        let addresses = resolved.addresses;
        FamilyGate::new(self.request.address_family, |family| Error::Family {
            family: family.label(),
        })
        .require(&addresses)?;
        for address in &addresses {
            if !self.report.resolved_addresses.contains(address) {
                self.report.resolved_addresses.push(*address);
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
            query_name: self.report.query_name.clone(),
            query_type: self.request.query_type,
            query: self.query.clone(),
        })
    }

    fn execute_probe(&mut self, probe: &Probe) -> Result<ProbeAttempt, Error> {
        let limits = self.request.limits;
        // The attempt window starts before the exchange and is shared with a
        // TCP fallback, which may use only what the exchange left of it.
        let mut attempt_deadline = Deadline::new(self.request.timeout);
        let (execution, grant) = self.execution.step(
            probe.attempt,
            self.request.timeout,
            &mut *self.executor,
            |executor, grant| {
                executor.execute(&Exchange {
                    probe: probe.clone(),
                    timeout: grant.timeout,
                    limits,
                    permit: grant.permit,
                })
            },
            |_, execution, grant, _| {
                validate_dns_execution(probe, execution, limits, grant.timeout)
            },
        )?;
        let _ = attempt_deadline.account(execution.stats.elapsed);
        Ok(ProbeAttempt {
            execution,
            timeout: grant.timeout,
            attempt_deadline,
        })
    }

    fn emit_attempt(&mut self, evidence: AttemptEvidence) -> Result<(), Error> {
        self.publish(
            evidence.attempt,
            Event::Attempt {
                context: Arc::clone(&self.context),
                evidence,
            },
        )
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
        self.report.completion.outcome = if metadata.truncated {
            Outcome::Truncated
        } else {
            Outcome::Response
        };
        self.report.completion.accepted_transport = Some(transport);
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
            self.publish(
                attempt,
                Event::Rejected {
                    attempt,
                    transport,
                    context: Arc::clone(&self.context),
                    record,
                },
            )?;
        }
        self.report.completion.response = Some(metadata);
        Ok(())
    }

    fn emit_record(
        &mut self,
        attempt: u32,
        transport: Transport,
        section: Section,
        record: Record,
    ) -> Result<(), Error> {
        self.publish(
            attempt,
            Event::Record {
                attempt,
                transport,
                context: Arc::clone(&self.context),
                section,
                record,
            },
        )
    }

    fn publish(&mut self, attempt: u32, event: Event) -> Result<(), Error> {
        (self.emit)(event, self.execution.deadline())?;
        self.execution.enforce(attempt)
    }

    fn retain_undecoded(&mut self, attempt: u32, frames: Vec<Frame>) -> Result<(), Error> {
        self.evidence.retain_undecoded(
            frames,
            &mut AttemptEvents {
                attempt,
                execution: &self.execution,
                emit: &mut *self.emit,
            },
        )
    }

    /// Records the diagnostics once, publishes every one not yet published,
    /// then checks the deadline.
    fn record_diagnostics(
        &mut self,
        attempt: u32,
        diagnostics: impl IntoIterator<Item = Diagnostic>,
    ) -> Result<(), Error> {
        self.evidence.record_diagnostics(
            diagnostics,
            &mut AttemptEvents {
                attempt,
                execution: &self.execution,
                emit: &mut *self.emit,
            },
        )?;
        self.execution.enforce(attempt)
    }
}

/// Publishes what the operation's evidence state keeps during one attempt as
/// DNS events.
struct AttemptEvents<'e, 'a, C, F> {
    attempt: u32,
    execution: &'e Context<'a, C, Attempts>,
    emit: &'e mut F,
}

impl<C, F> EvidenceSink for AttemptEvents<'_, '_, C, F>
where
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    type Error = Error;

    fn undecoded(&mut self, frame: Frame) -> Result<(), Error> {
        (self.emit)(
            Event::Undecoded(UndecodedEvidence {
                attempt: self.attempt,
                frame,
            }),
            self.execution.deadline(),
        )
    }

    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), Error> {
        (self.emit)(Event::Diagnostic(diagnostic), self.execution.deadline())
    }

    fn check(&mut self) -> Result<(), Error> {
        self.execution.enforce(self.attempt)
    }
}

fn select_response<'a>(
    registry: &Registry,
    probe: &Probe,
    execution: &'a mut ExchangeEvidence,
    limits: Limits,
    timeout: Duration,
    check: impl FnMut() -> Result<(), Error>,
) -> Result<Option<ResponseCandidate<'a, ResponseClassification>>, Error> {
    let sent_packet = &execution.sent.built().packet;
    // Validation admits only responses to the single query, request index 0.
    ResponseSelector::new(&mut execution.responses).select(
        0,
        timeout,
        |response| classify_response(registry, probe, sent_packet, response, limits.message),
        ResponseClassification::rank,
        |_| (),
        check,
    )
}

/// Names admission and execution-context failures as DNS errors at the retry
/// attempt they concern. The DNS batch runner's wait between questions
/// concerns the next question's first attempt.
pub(super) struct Attempts;

impl crate::execution::Errors for Attempts {
    type Error = Error;
    type Step = u32;

    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Error {
        Error::InvalidLimit {
            field,
            value,
            reason,
        }
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::Authorization(source)
    }

    fn duration_limit(&self, _: u32, source: DeadlineExceeded) -> Error {
        Error::from(source)
    }

    fn interrupted(&self, _: u32, source: Interrupted) -> Error {
        Error::from(source)
    }

    fn clock(&self, attempt: u32, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock { attempt, source }
    }

    fn execution(&self, attempt: u32, source: BoundaryError) -> Error {
        Error::Execution { attempt, source }
    }

    fn invalid_evidence(&self, attempt: u32, source: crate::evidence::Error) -> Error {
        Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::Exchange(source),
        }
    }

    fn stats_overflow(&self, attempt: u32, _: StatsOverflow) -> Error {
        Error::StatisticsOverflow { attempt }
    }
}
