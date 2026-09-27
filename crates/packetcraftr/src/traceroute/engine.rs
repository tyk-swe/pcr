// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::execution::{ExchangeExecutor, Executor, publisher};
use crate::policy::Authorizer;
use crate::probe::runner::{BatchEvidence, run_batches};
use crate::probe::{Batch, check_probe_count, check_probe_duration};
use crate::providers::Providers;
use crate::target::ResolveTarget;
use crate::target::{FamilyGate, admit_operation, wire_limits};
use crate::{Client, Sink};

use super::Error;
use super::MAX_PROBE_BYTES;
use super::WORKFLOW;
use super::error::Probes;
use super::evidence::ProbeClassifier;
use super::plan::{build_batches, worst_case_duration};
use super::{Event, Probe, Report, Request, Termination};
use crate::probe::{Transport, enforce_deadline};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Traces the route to the request's authorized destination one hop at a
    /// time and publishes each probe's final outcome, each retained undecoded
    /// frame, and each diagnostic to `sink`.
    ///
    /// The target and the complete packet, byte, and duration budget are
    /// authorized before any probe is built or any provider is consulted.
    /// Each hop's probes run as one exchange, and the trace stops after the
    /// hop that reaches the destination or reports it unreachable. The
    /// duration limit and the hop pacing are anchored on the client's clock.
    /// Each event is published on a worker admitted by the client's runtime,
    /// and the trace waits for the sink's answer before a later hop; the
    /// duration limit bounds that wait, not the sink itself, and confirmed
    /// sends are not undone.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the denied target or budget, the
    /// executor failure, inconsistent evidence, the exhausted duration limit
    /// or cancellation, or the sink's failure.
    pub fn traceroute<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let publish = publisher(
            &self.runtime,
            sink,
            |error| Probes.duration_limit(0, error),
            |source| Error::Output { source },
        )?;
        let send = crate::send::Options {
            destination: None,
            plan: request.route.clone(),
            build: packetcraftr_core::build::Options::default(),
            allow_permissive_live: false,
        };
        run(
            &request,
            &mut self.admission(),
            &self.registry,
            &mut ExchangeExecutor::new(self, send, request.collection.clone()),
            &mut self.clock.clone(),
            &mut self.deadline(request.limits.max_duration),
            publish,
        )
    }
}

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes hop batches until
/// checksum-valid evidence reaches the destination or reports it unreachable,
/// or `deadline` passes.
pub(crate) fn run<A, E, C, F>(
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
    E: Executor<Batch<Probe>>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let approved = approve_traceroute(request, authorizer, deadline)?;
    let mut batches = build_batches(request, approved.destination)?;
    enforce_deadline(&Probes, deadline)?;
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        Probes,
        request.limits.evidence(),
        ProbeClassifier {
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            termination: Termination::Timeout,
        },
        emit,
    );
    let stats = run_batches(
        &mut batches,
        request.probes_per_second,
        deadline,
        clock,
        executor,
        &mut evidence,
    )?;
    let termination = evidence.into_classifier().termination;

    Ok(Report {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        termination,
        stats,
    })
}

struct ApprovedTraceroute {
    declared_target: String,
    resolved_addresses: Vec<IpAddr>,
    destination: IpAddr,
}

fn approve_traceroute<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedTraceroute, Error> {
    request.validate()?;
    let (selected, _) = admit_operation(
        authorizer,
        deadline,
        &Probes,
        &request.target,
        FamilyGate::new(request.address_family, Error::family),
        |_| {
            let total_probes = request.total_probe_count()?;
            validate_probe_plan(request, total_probes)?;
            let maximum_wire_bytes = u64::try_from(total_probes)
                .unwrap_or(u64::MAX)
                .checked_mul(MAX_PROBE_BYTES)
                .ok_or(Error::InvalidLimit {
                    field: "wire_bytes",
                    value: u64::MAX,
                    reason: "wire-byte accounting overflowed".to_owned(),
                })?;
            Ok((total_probes, maximum_wire_bytes))
        },
        |plan| {
            Ok(wire_limits(
                u64::try_from(plan.0).unwrap_or(u64::MAX),
                plan.1,
            ))
        },
    )?;
    // The admission gate guarantees the selected set is non-empty.
    let destination = selected.addresses[0];
    Ok(ApprovedTraceroute {
        declared_target: selected.declared,
        resolved_addresses: selected.addresses,
        destination,
    })
}

fn validate_probe_plan(request: &Request, total_probes: usize) -> Result<(), Error> {
    check_probe_count(&Probes, total_probes, request.limits.max_probes)?;
    if let (Transport::Udp, Some(base)) = (request.strategy, request.destination_port) {
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > usize::from(u16::MAX))
        {
            return Err(Error::InvalidPort {
                message: format!(
                    "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                    total_probes
                ),
            });
        }
    }
    check_probe_duration(
        &Probes,
        worst_case_duration(request)?,
        request.limits.max_duration,
    )
}
