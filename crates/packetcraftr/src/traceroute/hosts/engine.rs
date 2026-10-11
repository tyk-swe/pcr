// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
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
    DeclaredTargets, FamilyGate, ResolveTarget, SelectedAddress, admit_resolved_selection,
    admit_selection, wire_limits,
};
use crate::traceroute::error::Probes;
use crate::traceroute::request::tcp_payload;
use crate::traceroute::{Error, MAX_PROBE_BYTES, Probe, WORKFLOW};
use crate::{Client, Sink, Stats};

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
        // The trace resolves its own neighbors, so its executor authorizes
        // each neighbor request like a probe whether or not the caller did.
        request.validate()?;
        let mut client = self
            .view_with_registry(std::sync::Arc::clone(&self.registry))
            .with_neighbor_request_authorization();
        if request.route.link_mode != packetcraftr_netio::link::Mode::Layer3
            && (request.strategy.is_some() || !request.observed.is_empty())
        {
            client.neighbors = client
                .neighbors
                .one_attempt(
                    request.timeout,
                    request.limits.evidence.max_frames,
                    request.limits.evidence.max_bytes,
                    request.collection.capture.snap_length,
                    request.limits.max_probes,
                )
                .map_err(|source| Error::Collection(BoundaryError::from_error(source)))?;
            // An implicit neighbor request waits on the trace's own rate
            // before its probe's batch.
            client.neighbor_pause =
                rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?;
        }
        let mut executor = super::executor::ClientExecutor::new(ExchangeExecutor::new(
            &client,
            send,
            request.collection.clone(),
        ));
        let mut report = run(
            &request,
            &mut self.admission(),
            &self.registry,
            &mut executor,
            &mut self.clock.clone(),
            &mut self.deadline(request.limits.max_duration),
            publish,
        )?;
        // The neighbor requests the probes' routes resolved count in the
        // operation's statistics; they were admitted in the plan's probe and
        // byte bounds already.
        report.neighbor_stats = executor.neighbor_stats().clone();
        report
            .stats
            .checked_add_assign(&report.neighbor_stats.clone())
            .map_err(|source| Probes.stats_overflow(0, source))?;
        Ok(report)
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
        request.limits.evidence,
        HostsClassifier {
            registry,
            batch: Vec::new(),
        },
        emit,
    );
    let mut planner = Planner::new(request, approved.slots);
    // Planning reads the shared clock itself so a blocking event sink cannot
    // leave stale anchor or reuse times for the next host.
    let planning_clock = clock.clone();
    let stats = run_planned(
        |evidence, _now, deadline| planner.next(evidence, || planning_clock.now(), deadline),
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
        neighbor_stats: Stats::default(),
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
    /// Trace probes plus the neighbor requests they may resolve.
    transmissions: usize,
    maximum_bytes: u64,
}

fn approve<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<Approved, Error> {
    request.validate()?;
    let declared = DeclaredTargets {
        selection: &request.targets,
        family: FamilyGate::new(request.address_family, Error::family),
        max_targets: request.max_targets,
    };
    // An exact resolved handoff re-authorizes every supplied target; the
    // bounded declaration still validates and gates for the report.
    let (selected, plan) = if let Some(resolved) = &request.resolved_targets {
        admit_resolved_selection(
            authorizer,
            deadline,
            &Probes,
            declared,
            resolved,
            Error::TargetSelection,
            |selected| plan_hosts(request, &selected.targets),
            |plan| {
                Ok(wire_limits(
                    u64::try_from(plan.transmissions).unwrap_or(u64::MAX),
                    plan.maximum_bytes,
                ))
            },
        )?
    } else {
        admit_selection(
            authorizer,
            deadline,
            &Probes,
            declared,
            Error::TargetSelection,
            |selected| plan_hosts(request, &selected.targets),
            |plan| {
                Ok(wire_limits(
                    u64::try_from(plan.transmissions).unwrap_or(u64::MAX),
                    plan.maximum_bytes,
                ))
            },
        )?
    };
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
    // A host over a link-layer route may resolve a fresh neighbor for each
    // of its probe batches: the operation cache usually serves them, but a
    // route that changed mid-plan could not be foreseen, so admission
    // reserves one possible request per trace probe.
    let mut neighbor_requests = 0_usize;
    let mut neighbor_bytes = 0_u64;
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
                if request.route.link_mode != packetcraftr_netio::link::Mode::Layer3
                    && !target.address.is_multicast()
                    && target.address != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
                {
                    neighbor_requests = neighbor_requests
                        .checked_add(host_probes)
                        .ok_or_else(|| overflow("probes"))?;
                    let request_bytes = match target.address {
                        IpAddr::V4(_) => crate::neighbor::IPV4_REQUEST_BYTES,
                        IpAddr::V6(_) => crate::neighbor::IPV6_REQUEST_BYTES,
                    };
                    neighbor_bytes = neighbor_bytes
                        .checked_add(
                            u64::try_from(host_probes)
                                .unwrap_or(u64::MAX)
                                .checked_mul(request_bytes)
                                .ok_or_else(|| overflow("wire_bytes"))?,
                        )
                        .ok_or_else(|| overflow("wire_bytes"))?;
                }
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
    // `max_probes` bounds every transmission the plan may send: the trace
    // probes plus the neighbor requests reserved for unrouted links.
    let transmissions = probes
        .checked_add(neighbor_requests)
        .ok_or_else(|| overflow("probes"))?;
    check_probe_count(&Probes, transmissions, request.limits.max_probes)?;
    check_probe_duration(
        &Probes,
        worst_case_duration(request, traced)?,
        request.limits.max_duration,
    )?;
    let maximum_bytes = u64::try_from(probes)
        .unwrap_or(u64::MAX)
        .checked_mul(MAX_PROBE_BYTES + u64::from(request.payload_size))
        .and_then(|bytes| bytes.checked_add(neighbor_bytes))
        .ok_or_else(|| overflow("wire_bytes"))?;
    Ok(Plan {
        slots,
        transmissions,
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
