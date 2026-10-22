// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::engine::admission::approve_operation;
use crate::engine::execution::Context;
use crate::engine::execution::evidence::EvidenceState;
use crate::engine::execution::{Executor, publisher};
use crate::exchange::WorkflowExecutor;
use crate::policy::Authorizer;
use crate::policy::{DnsOperation, Operation, WireLimits};
use crate::providers::{PacketProviders, TargetProviders, TcpProviders};
use crate::target::ResolveTarget;
use crate::{Client, Sink, Stats};

use super::EVIDENCE_DIAGNOSTICS;
use super::error::{Error, attempt_error};
use super::executor::{Exchange, TcpQuerier};
use super::plan::{OperationLimits, operation_limits};
use super::{Event, EventContext, Outcome, Report, Request, batch};

mod attempts;
mod tcp;

use attempts::Retries;

impl<P: PacketProviders + TargetProviders + TcpProviders, K: Clock> Client<P, K> {
    /// Runs one bounded DNS query and publishes its events as each becomes final.
    /// The query's worst-case traffic is authorized before any resolution.
    /// A sink may finish after this method returns while it holds a runtime worker permit.
    pub fn dns<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::engine::execution::Operation::new(self, request.limits.max_duration);
        self.dns_in(request, sink, &operation)
    }

    pub(crate) fn dns_in<S>(
        &self,
        request: Request,
        sink: S,
        operation: &crate::engine::execution::Operation,
    ) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let policy = operation.policy(&self.policy);
        let mut admission =
            crate::engine::admission::Admission::new(&policy, self.providers.resolver());
        let mut deadline = operation.deadline(self, request.limits.max_duration);
        let publish = publisher(&operation.runtime, sink, Error::from, |source| {
            Error::Output { source }
        })?;
        run(
            &request,
            &mut admission,
            &operation.registry,
            &mut WorkflowExecutor::new(
                self,
                operation,
                send_options(&request),
                request.collection.clone(),
            ),
            &mut self.clock.clone(),
            &mut deadline,
            publish,
        )
    }

    /// The traffic limits `questions` need together, for a workflow that
    /// splits more questions than one batch takes across batches to
    /// authorize once, as one operation, before the first; each batch still
    /// authorizes its own. The limits include every request this client's
    /// neighbor resolver may send before each UDP packet on a link-layer
    /// route.
    pub fn dns_limits<Q>(
        &self,
        questions: impl IntoIterator<Item = Q>,
    ) -> Result<DnsOperation, Error>
    where
        Q: std::borrow::Borrow<Request>,
    {
        batch::limits(questions, u64::from(self.neighbors.max_attempts()))
    }

    pub(crate) fn dns_limits_in<Q: std::borrow::Borrow<Request>>(
        &self,
        questions: impl IntoIterator<Item = Q>,
        operation: &crate::engine::execution::Operation,
    ) -> Result<DnsOperation, Error> {
        batch::limits(questions, u64::from(operation.neighbors.max_attempts()))
    }

    /// Runs DNS questions in input order under one deadline: the shortest `limits.max_duration`.
    /// Question failures are reported in the returned [`batch::Report`], not as errors.
    pub fn dns_batch<S>(&self, request: batch::Request, sink: S) -> Result<batch::Report, Error>
    where
        S: Sink<batch::Event, Ack = ()>,
    {
        let operation = crate::engine::execution::Operation::new(self, request.max_duration()?);
        self.dns_batch_in(request, sink, &operation)
    }

    pub(crate) fn dns_batch_in<S>(
        &self,
        request: batch::Request,
        sink: S,
        operation: &crate::engine::execution::Operation,
    ) -> Result<batch::Report, Error>
    where
        S: Sink<batch::Event, Ack = ()>,
    {
        let policy = operation.policy(&self.policy);
        let mut admission =
            crate::engine::admission::Admission::new(&policy, self.providers.resolver());
        let mut deadline = operation.deadline(self, request.max_duration()?);
        let publish = publisher(&operation.runtime, sink, Error::from, |source| {
            Error::Output { source }
        })?;
        let first = &request.questions[0];
        batch::run(
            &request,
            &mut admission,
            &operation.registry,
            &mut WorkflowExecutor::new(
                self,
                operation,
                send_options(first),
                first.collection.clone(),
            ),
            &mut self.clock.clone(),
            &mut deadline,
            publish,
        )
    }
}

fn send_options(request: &Request) -> crate::send::Options {
    crate::send::Options {
        plan: request.route.clone(),
        ..crate::send::Options::default()
    }
}

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
    // Approved before server resolution, unlike `admit_operation`'s resolve-first order.
    approve_operation(
        authorizer,
        Operation::Dns(prepared.limits),
        deadline,
        attempt_error,
    )?;
    prepared.execute(authorizer, registry, executor, clock, deadline, emit)?;
    Ok(prepared.report)
}

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

    /// The caller authorizes the cost first; endpoint authorization still runs per attempt.
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
            execution: Context::new(deadline, clock, attempt_error),
            query: self.query.clone(),
            delay: self.delay,
            context,
            report: &mut self.report,
            evidence: EvidenceState::new(self.request.limits.evidence, EVIDENCE_DIAGNOSTICS),
            emit: &mut emit,
        }
        .execute()
    }
}
