// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use super::planner::{HostsClassifier, Planner, Slot};
use super::report::{Event, Report};
use super::request::{Request, overflow};
use super::selection::{Choice, choose};
use crate::clock::Clock;
use crate::execution::{Errors as _, ExchangeExecutor, Executor, publisher, rate_delay};
use crate::policy::Authorizer;
use crate::probe::runner::{BatchEvidence, run_planned};
use crate::probe::{Batch, Transport, check_probe_count, check_probe_duration, enforce_deadline};
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::{
    DeclaredTargets, FamilyGate, ResolveTarget, SelectedAddress, admit_selection, wire_limits,
};
use crate::traceroute::error::Probes;
use crate::traceroute::request::{check_collection, tcp_payload};
use crate::traceroute::{Error, MAX_PROBE_BYTES, Probe, WORKFLOW};
use crate::{Client, Sink};

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    /// Traces every authorized host of the request under one finite plan and
    /// publishes each probe's final outcome, each host's record, each retained
    /// undecoded frame, and each diagnostic to `sink`.
    pub fn trace_hosts<S>(&self, request: Request, sink: S) -> Result<Report, Error>
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
    E: Executor<Batch<Probe>>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let approved = approve(request, authorizer, deadline)?;
    enforce_deadline(&Probes, deadline)?;
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        Probes,
        request.limits.evidence(),
        HostsClassifier {
            registry,
            batch: Vec::new(),
        },
        emit,
    );
    let mut planner = Planner::new(request, approved.slots);
    let stats = run_planned(
        |evidence, now, deadline| planner.next(evidence, now, deadline),
        request.probes_per_second,
        request.paced_after,
        deadline,
        clock,
        executor,
        &mut evidence,
    )?;
    let retained_evidence_bytes = evidence.retained_evidence_bytes();

    Ok(Report {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        hosts: planner.into_hosts(),
        reuse: request.reuse,
        retained_evidence_bytes,
        stats,
    })
}

struct Approved {
    declared_target: String,
    resolved_addresses: Vec<IpAddr>,
    slots: Vec<Slot>,
}

struct Plan {
    slots: Vec<Slot>,
    probes: usize,
    maximum_bytes: u64,
}

fn approve<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<Approved, Error> {
    request.validate()?;
    check_collection(&request.collection, &request.limits, request.probes_per_hop)?;
    let (selected, plan) = admit_selection(
        authorizer,
        deadline,
        &Probes,
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.max_targets,
        },
        Error::TargetSelection,
        |selected| plan_hosts(request, &selected.targets),
        |plan| {
            Ok(wire_limits(
                u64::try_from(plan.probes).unwrap_or(u64::MAX),
                plan.maximum_bytes,
            ))
        },
    )?;
    Ok(Approved {
        declared_target: selected.declared.clone(),
        resolved_addresses: selected.addresses(),
        slots: plan.slots,
    })
}

fn plan_hosts(request: &Request, targets: &[SelectedAddress]) -> Result<Plan, Error> {
    let observations: HashMap<_, _> = request
        .observed
        .iter()
        .map(|observed| (observed.address, observed))
        .collect();
    let host_probes = request.host_probe_cap()?;
    let mut traced = 0_usize;
    let mut slots = Vec::with_capacity(targets.len());
    for target in targets {
        let trace = match choose(request, &observations, target) {
            Choice::NotTraced(reason) => Err(reason),
            Choice::Traced(selection) => {
                let strategy = selection.strategy;
                if request.dont_fragment && target.address.is_ipv6() {
                    return Err(Error::InvalidProbeOption {
                        option: "dont_fragment",
                        reason:
                            "the IPv4 Don't Fragment flag does not exist for an IPv6 destination"
                                .to_owned(),
                    });
                }
                if strategy.transport == Transport::Tcp && request.payload_size > 0 {
                    return Err(tcp_payload());
                }
                if let (Transport::Udp, Some(base)) =
                    (strategy.transport, strategy.destination_port)
                {
                    let last = u64::try_from(host_probes.saturating_sub(1)).unwrap_or(u64::MAX);
                    if u64::from(base).saturating_add(last) > u64::from(u16::MAX) {
                        return Err(Error::InvalidPort {
                            message: format!(
                                "base UDP port {base} plus probe {last} exceeds {}",
                                u16::MAX
                            ),
                        });
                    }
                }
                traced += 1;
                Ok(selection)
            }
        };
        slots.push(Slot {
            address: target.address,
            scope: target.scope.clone(),
            trace,
        });
    }
    let probes = traced
        .checked_mul(host_probes)
        .ok_or_else(|| overflow("probes"))?;
    check_probe_count(&Probes, probes, request.limits.max_probes)?;
    check_probe_duration(
        &Probes,
        worst_case_duration(request, traced)?,
        request.limits.max_duration,
    )?;
    let maximum_bytes = u64::try_from(probes)
        .unwrap_or(u64::MAX)
        .checked_mul(MAX_PROBE_BYTES + u64::from(request.payload_size))
        .ok_or_else(|| overflow("wire_bytes"))?;
    Ok(Plan {
        slots,
        probes,
        maximum_bytes,
    })
}

fn worst_case_duration(request: &Request, traced: usize) -> Result<Duration, Error> {
    let overflowed = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    };
    let batches =
        u32::try_from(traced.saturating_mul(request.hop_count())).map_err(|_| overflowed())?;
    let exchange = request
        .timeout
        .checked_mul(batches)
        .ok_or_else(overflowed)?;
    let delay = rate_delay(
        &Probes,
        "probes_per_second",
        usize::try_from(request.probes_per_hop).unwrap_or(usize::MAX),
        request.probes_per_second,
    )?
    .checked_mul(batches.saturating_sub(1))
    .ok_or_else(overflowed)?;
    let initial = if request.paced_after.is_some() && batches > 0 {
        rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?
    } else {
        Duration::ZERO
    };
    exchange
        .checked_add(delay)
        .and_then(|total| total.checked_add(initial))
        .ok_or_else(overflowed)
}
