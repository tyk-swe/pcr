// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod batch_evidence;

pub(crate) use batch_evidence::{BatchEvidence, Classifier, NO_RESPONSE_REASON, Outcome};

use std::borrow::BorrowMut;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::execution::Executor;
use crate::execution::{Context, Errors, Grant, Receipt, rate_delay};
use crate::{Stats, evidence::SentPacket};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Batch<P> {
    pub(crate) probes: Vec<P>,
    pub(crate) timeout: Duration,
    pub(crate) permit: ExecutionPermit,
    pub(crate) sequence: u64,
}

impl<P> Batch<P> {
    fn bind(&mut self, grant: Grant) {
        self.timeout = grant.timeout;
        self.permit = grant.permit;
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UnsolicitedCapture {
    pub(crate) decoded: DecodedPacket,
    pub(crate) received_at: Option<Instant>,
    pub(crate) response_deadline: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct Evidence {
    pub(crate) permit: ExecutionPermit,
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<UnsolicitedCapture>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl Evidence {
    pub(crate) fn from_exchange(
        permit: ExecutionPermit,
        result: crate::exchange::WorkflowEvidence,
    ) -> Self {
        let crate::exchange::Aggregate {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result.aggregate;
        let unsolicited = unsolicited
            .into_iter()
            .zip(result.unsolicited_ingress)
            .map(|(decoded, received_at)| UnsolicitedCapture {
                decoded,
                received_at,
                response_deadline: result.response_deadline,
            })
            .collect();
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

impl Receipt for Evidence {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
    }
}

impl<P> crate::execution::Step for Batch<P> {
    type Evidence = Evidence;
}

pub(crate) trait Sequenced {
    fn sequence(&self) -> u64;
}

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
