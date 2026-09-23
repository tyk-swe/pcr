// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::progress::Runtime;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::BoundaryError;
use crate::clock::Clock;
use crate::policy::Authorizer;
use crate::probe::evidence::{check_probe_count, check_probe_duration};
use crate::probe::runner::{BatchEvidence, run_batches, sink_observer};
use crate::target::{GateErrors, admit_operation, budgeted};

use super::MAX_PROBE_BYTES;
use super::WORKFLOW;
use super::evidence::ProbeClassifier;
use super::plan::{build_batches, worst_case_duration};
use super::{Batch, Completion, Event, Hop, Report, Request, Summary, UndecodedEvidence};
use crate::probe::{Error, ErrorKind, Executor, Transport, enforce_deadline, index_or_push};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes hop batches until
/// checksum-valid evidence reaches the destination or reports it unreachable.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<Batch>,
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

/// Executes one approved trace and publishes each final probe outcome and
/// retained undecoded frame before starting a later hop. The callback runs on
/// a runtime-budgeted worker. `max_duration` bounds publisher waiting and deadline-aware live
/// I/O, not arbitrary callback execution. Confirmed sends in the current hop
/// are not undone, callback failure prevents later hops, and a callback may
/// finish after this function returns while holding its permit.
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
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
        runtime,
        emit,
        |error| WORKFLOW.duration_limit(error.actual, error.limit),
        |source| Error::new(WORKFLOW, ErrorKind::Output { source }),
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
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    enforce_deadline(WORKFLOW, &deadline)?;
    let approved = approve_traceroute(request, authorizer, &deadline)?;
    let mut batches = build_batches(request, approved.destination)?;
    enforce_deadline(WORKFLOW, &deadline)?;
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        request.limits.evidence(),
        ProbeClassifier {
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            completion: Completion::Timeout,
        },
        emit,
    );
    let stats = run_batches(
        &mut batches,
        request.probes_per_second,
        &mut deadline,
        clock,
        executor,
        &mut evidence,
    )?;
    let completion = evidence.into_classifier().completion;

    Ok(Summary {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        completion,
        stats,
    })
}

#[derive(Default)]
pub(super) struct Collector {
    hops: Vec<Hop>,
    hop_indices: HashMap<u8, usize>,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    pub(super) fn observe(&mut self, event: Event) {
        match event {
            Event::Probe { target: _, probe } => {
                let hop = index_or_push(
                    &mut self.hops,
                    &mut self.hop_indices,
                    probe.hop_limit,
                    || Hop {
                        hop_limit: probe.hop_limit,
                        probes: Vec::new(),
                    },
                );
                hop.probes.push(probe);
            }
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    pub(super) fn finish(self, summary: Summary) -> Report {
        Report {
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            destination: summary.destination,
            strategy: summary.strategy,
            destination_port: summary.destination_port,
            hops: self.hops,
            undecoded: self.undecoded,
            completion: summary.completion,
            diagnostics: self.diagnostics,
            stats: summary.stats,
        }
    }
}

struct ApprovedTraceroute {
    declared_target: String,
    resolved_addresses: Vec<IpAddr>,
    destination: IpAddr,
}

fn approve_traceroute<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedTraceroute, Error> {
    request.validate()?;
    let (selected, _) = admit_operation(
        authorizer,
        deadline,
        &WORKFLOW,
        &request.target,
        request.address_family,
        |_| {
            let total_probes = request.total_probe_count()?;
            validate_probe_plan(request, total_probes)?;
            let maximum_wire_bytes = u64::try_from(total_probes)
                .unwrap_or(u64::MAX)
                .checked_mul(MAX_PROBE_BYTES)
                .ok_or(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidLimit {
                        field: "wire_bytes",
                        value: u64::MAX,
                        reason: "wire-byte accounting overflowed".to_owned(),
                    },
                ))?;
            Ok((total_probes, maximum_wire_bytes))
        },
        |plan| Ok(budgeted(u64::try_from(plan.0).unwrap_or(u64::MAX), plan.1)),
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
    check_probe_count(WORKFLOW, total_probes, request.limits.max_probes)?;
    if let (Transport::Udp, Some(base)) = (request.strategy, request.destination_port) {
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > usize::from(u16::MAX))
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidPort {
                    message: format!(
                        "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                        total_probes
                    ),
                },
            ));
        }
    }
    check_probe_duration(
        WORKFLOW,
        worst_case_duration(request)?,
        request.limits.max_duration,
    )
}
