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

use packetcraftr_capture::Frame;
use packetcraftr_packet::{decode::Result as DecodedPacket, diagnostic::Diagnostic};

use super::address_family::AddressFamily;
use super::clock::{Clock, rate_delay};
use super::evidence::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, MatchedResponseEvidence, ResponseCandidate,
    push_undecoded_limit_diagnostic, retain_evidence, select_response_candidate,
};
use super::target::{Authorizer, Target};
use super::{BoundaryError, Stats};
use packetcraftr_core::budget::Deadline;

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

#[derive(Clone, Copy, Debug)]
pub(super) struct ProbeRunConfig {
    pub(super) probes_per_second: Option<u32>,
    pub(super) duration_limit: Duration,
    pub(super) final_statistics_sequence: u64,
}

/// Workflow-owned operations and error taxonomy for the shared probe runner.
pub(super) trait ProbeLifecycle<B> {
    type Execution: ProbeExecution;
    type Output;
    type Error;

    fn execute(&mut self, batch: &B) -> Result<Self::Execution, BoundaryError>;
    fn validate(&mut self, batch: &B, execution: &Self::Execution) -> Result<(), Self::Error>;
    fn process(
        &mut self,
        batch: &B,
        execution: Self::Execution,
        deadline: &Deadline,
    ) -> Result<Self::Output, Self::Error>;
    fn should_stop(output: &Self::Output) -> bool;
    fn duration_error(actual: Duration, limit: Duration) -> Self::Error;
    fn rate_error(rate: Option<u32>) -> Self::Error;
    fn clock_error(sequence: u64, message: String) -> Self::Error;
    fn execution_error(sequence: u64, source: BoundaryError) -> Self::Error;
    fn statistics_error(sequence: u64) -> Self::Error;
}

/// Stable, linear-time response grouping shared by every bounded probe batch.
/// Sorting is stable so equal request indices preserve executor evidence order.
pub(super) struct ResponseSelector<'a, M> {
    matched: Peekable<Iter<'a, M>>,
    unsolicited: &'a [DecodedPacket],
    consumed_unsolicited: HashSet<usize>,
}

impl<'a, M: MatchedResponseEvidence> ResponseSelector<'a, M> {
    pub(super) fn new(matched: &'a mut [M], unsolicited: &'a [DecodedPacket]) -> Self {
        matched.sort_by_key(MatchedResponseEvidence::request_index);
        Self {
            matched: matched.iter().peekable(),
            unsolicited,
            consumed_unsolicited: HashSet::new(),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the selection seam threads request identity, timing, and the caller's fallible \
                  callbacks; a parameter struct would only rename the same fields"
    )]
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
        let mut best_unsolicited = None;
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
            if let Some(observation) = classify(response.response())
                && select_response_candidate(
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
                )
            {
                best_unsolicited = None;
            }
            check_deadline()?;
        }
        for (index, response) in self.unsolicited.iter().enumerate() {
            if self.consumed_unsolicited.contains(&index) {
                continue;
            }
            check_deadline()?;
            if let Some(observation) = classify(response)
                && select_response_candidate(
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
                )
            {
                best_unsolicited = Some(index);
            }
            check_deadline()?;
        }
        if let Some(index) = best_unsolicited {
            self.consumed_unsolicited.insert(index);
        }
        Ok(best)
    }
}

/// Applies the operation-wide evidence budget and undecoded retention cap in
/// one place while allowing workflows to retain their own typed wrapper.
#[expect(
    clippy::too_many_arguments,
    reason = "the retention seam threads the frame batch, its output sink, and every bound that \
              caps it; a parameter struct would only rename the same fields"
)]
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
pub(super) fn run_batches<B, L, C>(
    batches: &[B],
    config: ProbeRunConfig,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<BatchRun<L::Output>, L::Error>
where
    B: ProbeBatch,
    L: ProbeLifecycle<B>,
    C: Clock,
{
    let mut outputs = Vec::with_capacity(batches.len());
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        check_deadline(deadline, L::duration_error)?;
        let sequence = batch.sequence();
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probe_count(),
                config.probes_per_second,
            )
            .ok_or_else(|| L::rate_error(config.probes_per_second))?;
            check_deadline(deadline, L::duration_error)?;
            deadline
                .start_accounting(delay)
                .map_err(|error| L::duration_error(error.actual, error.limit))?;
            clock
                .sleep(delay)
                .map_err(|source| L::clock_error(sequence, source.to_string()))?;
            deadline
                .account(delay)
                .map_err(|error| L::duration_error(error.actual, error.limit))?;
            scheduled_delay = scheduled_delay
                .checked_add(delay)
                .ok_or_else(|| L::duration_error(Duration::MAX, config.duration_limit))?;
        }

        check_deadline(deadline, L::duration_error)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(|error| L::duration_error(error.actual, error.limit))?;
        let execution = lifecycle
            .execute(batch)
            .map_err(|source| L::execution_error(sequence, source))?;
        check_deadline(deadline, L::duration_error)?;
        deadline
            .account(execution.stats().elapsed)
            .map_err(|error| L::duration_error(error.actual, error.limit))?;
        lifecycle.validate(batch, &execution)?;
        check_deadline(deadline, L::duration_error)?;
        stats
            .checked_add(execution.stats())
            .ok_or_else(|| L::statistics_error(sequence))?;
        let output = lifecycle.process(batch, execution, deadline)?;
        let stop = L::should_stop(&output);
        outputs.push(output);
        if stop {
            break;
        }
    }

    check_deadline(deadline, L::duration_error)?;
    stats.elapsed = stats
        .elapsed
        .checked_add(scheduled_delay)
        .ok_or_else(|| L::statistics_error(config.final_statistics_sequence))?;
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::UNIX_EPOCH;

    use packetcraftr_capture::LinkType;
    use packetcraftr_packet::{Packet, layout};

    use super::super::evidence::ResponseEvidence;
    use super::*;

    struct NoMatchedResponses;

    impl ResponseEvidence for NoMatchedResponses {
        fn response(&self) -> &DecodedPacket {
            unreachable!("the fixture has no matched responses")
        }

        fn latency(&self) -> Duration {
            unreachable!("the fixture has no matched responses")
        }
    }

    impl MatchedResponseEvidence for NoMatchedResponses {
        fn request_index(&self) -> usize {
            unreachable!("the fixture has no matched responses")
        }
    }

    #[test]
    fn one_unsolicited_frame_can_satisfy_only_one_probe() {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_millis(1),
            LinkType::RAW,
            &[1_u8][..],
        )
        .unwrap();
        let response = DecodedPacket {
            packet: Packet::new(),
            original: frame.bytes().clone(),
            frame,
            layout: layout::Packet::default(),
            diagnostics: Vec::new(),
        };
        let mut matched = Vec::<NoMatchedResponses>::new();
        let mut selector = ResponseSelector::new(&mut matched, std::slice::from_ref(&response));

        let first = selector
            .select(
                0,
                UNIX_EPOCH,
                Duration::from_millis(10),
                |_| Some(()),
                |_| 0,
                |_| (),
                || Ok::<(), Infallible>(()),
            )
            .unwrap();
        assert!(first.is_some());
        let second = selector
            .select(
                1,
                UNIX_EPOCH,
                Duration::from_millis(10),
                |_| Some(()),
                |_| 0,
                |_| (),
                || Ok::<(), Infallible>(()),
            )
            .unwrap();
        assert!(second.is_none());
    }
}
