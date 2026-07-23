// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.
//!
//! Scan and traceroute deliberately keep their probe construction,
//! classification, aggregation, and public errors. This module owns only the
//! policy-sensitive mechanics whose ordering must stay identical.

use std::collections::HashSet;
use std::iter::Peekable;
use std::net::IpAddr;
use std::slice::Iter;
use std::time::{Duration, SystemTime};

use crate::capture::Frame;
use crate::packet::{decode::Result as DecodedPacket, diagnostic::Diagnostic};

use super::address_family::AddressFamily;
use super::clock::{Clock, rate_delay};
use super::deadline::Deadline;
use super::evidence::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, MatchedResponseEvidence, ResponseCandidate,
    push_undecoded_limit_diagnostic, retain_evidence, select_response_candidate,
};
use super::target::{Authorizer, Target};
use super::{BoundaryError, Stats};

pub(super) struct SelectedTargets {
    pub(super) declared: String,
    pub(super) addresses: Vec<IpAddr>,
}

/// Resolves, authorizes, filters, and de-duplicates a target while checking
/// the same absolute deadline on both sides of every policy boundary.
pub(super) fn resolve_selected<A, E>(
    authorizer: &mut A,
    target: &Target,
    family: AddressFamily,
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<SelectedTargets, E>
where
    A: Authorizer,
    E: From<BoundaryError>,
{
    check_deadline(deadline, &mut duration_error)?;
    let resolved = authorizer.resolve_and_authorize(target);
    check_deadline(deadline, &mut duration_error)?;
    let resolved = resolved.map_err(E::from)?;

    let mut addresses = Vec::with_capacity(resolved.addresses.len());
    let mut seen = HashSet::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        check_deadline(deadline, &mut duration_error)?;
        if family.accepts(address) && seen.insert(address) {
            addresses.push(address);
        }
    }
    Ok(SelectedTargets {
        declared: resolved.declared,
        addresses,
    })
}

/// Obtains complete packet and byte approval before batch construction or
/// execution can produce live side effects.
pub(super) fn approve_operation<A, E>(
    authorizer: &mut A,
    packets: u64,
    maximum_wire_bytes: u64,
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<(), E>
where
    A: Authorizer,
    E: From<BoundaryError>,
{
    check_deadline(deadline, &mut duration_error)?;
    let approval = authorizer.authorize_operation(packets, maximum_wire_bytes);
    check_deadline(deadline, &mut duration_error)?;
    approval.map_err(E::from)
}

pub(super) trait ProbeBatch {
    fn sequence(&self) -> u64;
    fn probe_count(&self) -> usize;
}

pub(super) trait ProbeExecution {
    fn stats(&self) -> &Stats;
}

pub(super) struct BatchRun<O> {
    pub(super) outputs: Vec<O>,
    pub(super) stats: Stats,
}

/// Stable, linear-time response grouping shared by every bounded probe batch.
/// Sorting is stable so equal request indices preserve executor evidence order.
pub(super) struct ResponseSelector<'a, M> {
    matched: Peekable<Iter<'a, M>>,
    unsolicited: &'a [DecodedPacket],
}

impl<'a, M: MatchedResponseEvidence> ResponseSelector<'a, M> {
    pub(super) fn new(matched: &'a mut [M], unsolicited: &'a [DecodedPacket]) -> Self {
        matched.sort_by_key(MatchedResponseEvidence::request_index);
        Self {
            matched: matched.iter().peekable(),
            unsolicited,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn select<O, K: Ord, E>(
        &mut self,
        request_index: usize,
        sent_at: SystemTime,
        timeout: Duration,
        mut classify: impl FnMut(&DecodedPacket) -> Option<O>,
        rank: impl Fn(&O) -> u8,
        tie_break_key: impl Fn(&O) -> K,
        mut check_deadline: impl FnMut() -> Result<(), E>,
    ) -> Result<Option<ResponseCandidate<'a, O>>, E> {
        let mut best = None;
        while self
            .matched
            .peek()
            .is_some_and(|response| response.request_index() == request_index)
        {
            check_deadline()?;
            let response = self
                .matched
                .next()
                .expect("peeked matched response must remain available");
            if let Some(observation) = classify(response.response()) {
                select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response.response(),
                        latency: Some(response.latency()),
                    },
                    sent_at,
                    timeout,
                    &rank,
                    &tie_break_key,
                );
            }
            check_deadline()?;
        }
        for response in self.unsolicited {
            check_deadline()?;
            if let Some(observation) = classify(response) {
                select_response_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response,
                        latency: None,
                    },
                    sent_at,
                    timeout,
                    &rank,
                    &tie_break_key,
                );
            }
            check_deadline()?;
        }
        Ok(best)
    }
}

/// Applies the operation-wide evidence budget and undecoded retention cap in
/// one place while allowing workflows to retain their own typed wrapper.
#[allow(clippy::too_many_arguments)]
pub(super) fn retain_undecoded_frames<T, E>(
    frames: Vec<Frame>,
    output: &mut Vec<T>,
    max_undecoded: usize,
    budget: &mut EvidenceBudget,
    descriptor: EvidenceDiagnosticDescriptor,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    diagnostics: &mut Vec<Diagnostic>,
    mut map: impl FnMut(Frame) -> T,
    mut check_deadline: impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    for frame in frames {
        check_deadline()?;
        if output.len() >= max_undecoded {
            push_undecoded_limit_diagnostic(diagnostics, descriptor, max_undecoded);
            break;
        }
        if retain_evidence(
            budget,
            &frame,
            descriptor,
            max_evidence_frames,
            max_evidence_bytes,
            diagnostics,
        ) {
            output.push(map(frame));
        }
        check_deadline()?;
    }
    Ok(())
}

/// Runs already-approved homogeneous batches with shared deadline, pacing,
/// executor-boundary, evidence-validation, and checked-statistics policy.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_batches<B, X, O, E, C>(
    batches: &[B],
    probes_per_second: Option<u32>,
    duration_limit: Duration,
    final_statistics_sequence: u64,
    deadline: &mut Deadline,
    clock: &mut C,
    mut execute: impl FnMut(&B) -> Result<X, BoundaryError>,
    mut validate: impl FnMut(&B, &X) -> Result<(), E>,
    mut process: impl FnMut(&B, X, &Deadline) -> Result<O, E>,
    mut should_stop: impl FnMut(&O) -> bool,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
    mut rate_error: impl FnMut(Option<u32>) -> E,
    mut clock_error: impl FnMut(u64, String) -> E,
    mut execution_error: impl FnMut(u64, BoundaryError) -> E,
    mut statistics_error: impl FnMut(u64) -> E,
) -> Result<BatchRun<O>, E>
where
    B: ProbeBatch,
    X: ProbeExecution,
    C: Clock,
{
    let mut outputs = Vec::with_capacity(batches.len());
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        check_deadline(deadline, &mut duration_error)?;
        let sequence = batch.sequence();
        if batch_index != 0 {
            let delay = rate_delay(batches[batch_index - 1].probe_count(), probes_per_second)
                .ok_or_else(|| rate_error(probes_per_second))?;
            check_deadline(deadline, &mut duration_error)?;
            deadline
                .start_accounting(delay)
                .map_err(|error| duration_error(error.actual, error.limit))?;
            clock
                .sleep(delay)
                .map_err(|source| clock_error(sequence, source.to_string()))?;
            deadline
                .account(delay)
                .map_err(|error| duration_error(error.actual, error.limit))?;
            scheduled_delay = scheduled_delay
                .checked_add(delay)
                .ok_or_else(|| duration_error(Duration::MAX, duration_limit))?;
        }

        check_deadline(deadline, &mut duration_error)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(|error| duration_error(error.actual, error.limit))?;
        let execution = execute(batch);
        check_deadline(deadline, &mut duration_error)?;
        let execution = execution.map_err(|source| execution_error(sequence, source))?;
        deadline
            .account(execution.stats().elapsed)
            .map_err(|error| duration_error(error.actual, error.limit))?;
        validate(batch, &execution)?;
        check_deadline(deadline, &mut duration_error)?;
        stats
            .checked_add(execution.stats())
            .ok_or_else(|| statistics_error(sequence))?;
        let output = process(batch, execution, deadline)?;
        let stop = should_stop(&output);
        outputs.push(output);
        if stop {
            break;
        }
    }

    check_deadline(deadline, &mut duration_error)?;
    stats.elapsed = stats
        .elapsed
        .checked_add(scheduled_delay)
        .ok_or_else(|| statistics_error(final_statistics_sequence))?;
    Ok(BatchRun { outputs, stats })
}

pub(super) fn check_deadline<E>(
    deadline: &Deadline,
    mut duration_error: impl FnMut(Duration, Duration) -> E,
) -> Result<(), E> {
    deadline
        .check()
        .map_err(|error| duration_error(error.actual, error.limit))
}
