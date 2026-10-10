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
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::ResolveTarget;
use crate::target::{FamilyGate, admit_operation, wire_limits};
use crate::{Client, Sink};

use super::Error;
use super::MAX_PROBE_BYTES;
use super::WORKFLOW;
use super::error::Probes;
use super::evidence::ProbeClassifier;
use super::plan::{build_batches, probe_target, worst_case_duration};
use super::{Event, Probe, Report, Request, Termination};
use crate::probe::enforce_deadline;

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    /// Traces the route to the request's authorized destination one hop at a
    /// time and publishes each probe's final outcome, each retained undecoded
    /// frame, and each diagnostic to `sink`.
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
    let retained_evidence_bytes = evidence.retained_evidence_bytes();
    let termination = evidence.into_classifier().termination;

    Ok(Report {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        termination,
        retained_evidence_bytes,
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
    super::request::check_collection(&request.collection, &request.limits, request.probes_per_hop)?;
    let (selected, _) = admit_operation(
        authorizer,
        deadline,
        &Probes,
        &request.target,
        FamilyGate::new(request.address_family, Error::family),
        |selected| {
            if selected.targets.iter().any(|target| target.scope.is_some()) {
                return Err(Error::ScopedTarget {
                    target: selected.declared.clone(),
                });
            }
            if request.dont_fragment
                && selected
                    .targets
                    .first()
                    .is_some_and(|target| target.address.is_ipv6())
            {
                return Err(Error::InvalidProbeOption {
                    option: "dont_fragment",
                    reason: "the IPv4 Don't Fragment flag does not exist for an IPv6 destination"
                        .to_owned(),
                });
            }
            let total_probes = request.total_probe_count()?;
            validate_probe_plan(request, total_probes)?;
            let maximum_wire_bytes = u64::try_from(total_probes)
                .unwrap_or(u64::MAX)
                .checked_mul(MAX_PROBE_BYTES + u64::from(request.payload_size))
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
    let destination = selected.targets[0].address;
    let resolved_addresses = selected.addresses();
    Ok(ApprovedTraceroute {
        declared_target: selected.declared,
        resolved_addresses,
        destination,
    })
}

fn validate_probe_plan(request: &Request, total_probes: usize) -> Result<(), Error> {
    check_probe_count(&Probes, total_probes, request.limits.max_probes)?;
    probe_target(
        request,
        u64::try_from(total_probes.saturating_sub(1)).unwrap_or(u64::MAX),
    )?;
    check_probe_duration(
        &Probes,
        worst_case_duration(request)?,
        request.limits.max_duration,
    )
}
