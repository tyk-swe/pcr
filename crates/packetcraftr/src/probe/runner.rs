// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

mod batch_evidence;

pub(crate) use batch_evidence::{BatchEvidence, Classifier, NO_RESPONSE_REASON, Outcome};

use std::borrow::BorrowMut;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::execution::Executor;
use crate::execution::{Context, Errors, Grant, Receipt, rate_delay};
use crate::{SentPacket, Stats};

/// A planned batch of probes executed together: one probe per scan batch,
/// one hop's probes per traceroute batch. Never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<P> {
    pub probes: Vec<P>,
    pub timeout: Duration,
    pub(crate) permit: ExecutionPermit,
    /// The first probe's operation-local sequence, recorded by the planner
    /// that built the batch; it names the batch in every error the runner
    /// reports.
    pub(crate) sequence: u64,
}

impl<P> Batch<P> {
    /// Binds the execution context's grant so the executor runs the batch
    /// under the clipped timeout and returns evidence for the fresh permit.
    fn bind(&mut self, grant: Grant) {
        self.timeout = grant.timeout;
        self.permit = grant.permit;
    }
}

/// Common executor evidence returned by homogeneous probe batches.
#[derive(Clone, Debug)]
pub struct Execution {
    pub(crate) permit: ExecutionPermit,
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl Execution {
    pub(crate) fn from_exchange(permit: ExecutionPermit, result: crate::exchange::Report) -> Self {
        let crate::exchange::Report {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let sent = sent
            .into_iter()
            .map(crate::exchange::into_sent_packet)
            .collect();
        Self {
            permit,
            sent,
            responses,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        }
    }
}

impl Receipt for Execution {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
}

impl<P> crate::execution::Request for Batch<P> {
    type Execution = Execution;
}

pub(crate) trait Sequenced {
    fn sequence(&self) -> u64;
}

/// Runs already-approved homogeneous batches through the execution context,
/// which owns deadline, pacing, permit, timeout-clipping, and checked-statistics
/// policy, and hands each batch's evidence to `evidence`, which validates it
/// inside the step and processes it after. The runner supplies the pacing
/// input: each batch waits for the previous batch's probe count at
/// `probes_per_second`. A batch whose processing breaks ends the operation.
pub(crate) fn run_batches<E, C, K, F, G>(
    batches: impl IntoIterator<Item = impl BorrowMut<Batch<K::Probe>>>,
    probes_per_second: Option<u32>,
    deadline: &mut Deadline,
    clock: &mut C,
    executor: &mut E,
    evidence: &mut BatchEvidence<K, F, G>,
) -> Result<Stats, G::Error>
where
    E: Executor<Batch<K::Probe>>,
    C: Clock,
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), G::Error>,
    G: Errors<Step = u64> + Copy,
{
    let errors = evidence.errors();
    let mut context = Context::new(deadline, clock, errors);
    let mut previous_probes = None;
    let mut last_sequence = 0;

    for mut planned in batches {
        let batch = planned.borrow_mut();
        let sequence = batch.sequence;
        context.enforce(sequence)?;
        if let Some(previous_probes) = previous_probes {
            let delay = rate_delay(
                &errors,
                "probes_per_second",
                previous_probes,
                probes_per_second,
            )?;
            context.pace(sequence, delay)?;
        }
        previous_probes = Some(batch.probes.len());
        last_sequence = sequence;

        let (execution, _) = context.step(
            sequence,
            batch.timeout,
            &mut (&mut *batch, &mut *executor),
            |(batch, executor), grant| {
                batch.bind(grant);
                executor.execute(batch)
            },
            |(batch, _), execution, _, _| evidence.validate(batch, execution),
        )?;
        if evidence
            .process(batch, execution, context.deadline())?
            .is_break()
        {
            break;
        }
    }

    context.enforce(last_sequence)?;
    Ok(context.into_stats())
}

#[cfg(test)]
mod tests;
