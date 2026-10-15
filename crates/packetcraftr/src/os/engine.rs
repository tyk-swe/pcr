// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::{budget::Deadline, document::os_fingerprints as core, registry::Registry};

use super::{
    Collector, Error, Event, Match, Outcome, Probe, Report, Request,
    error::probe_error,
    evidence::Fingerprints,
    executor::{Native, OsExecutor},
    plan::PlannedProbe,
};
use crate::{
    Client, Sink,
    clock::Clock,
    policy::Authorizer,
    probe::{
        Workflow,
        runner::{Batch, BatchEvidence, run_planned},
    },
    providers::{PacketProviders, TargetProviders},
    target::{Family, FamilyGate, ResolveTarget, admit_operation, wire_limits},
};

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    pub fn identify_os<S: Sink<Event, Ack = ()>>(
        &self,
        request: Request,
        sink: S,
    ) -> Result<Report, Error> {
        request.validate()?;
        let mut operation = crate::execution::Operation::new(self, request.limits.max_duration);
        let mut deadline = operation.deadline(self, request.limits.max_duration);
        let publish =
            crate::execution::publisher(&self.runtime, sink, Error::Deadline, Error::Output)?;
        let mut clock = self.clock.clone();
        let mut authorizer = self.admission();
        operation.neighbors = self.neighbors.for_operation(1);
        operation.neighbor_mode = crate::execution::NeighborMode::Cached;
        operation.packet_limit = request.limits.max_probes as u64;
        operation.byte_limit = request.limits.max_probes as u64 * super::MAX_WIRE_BYTES;
        let mut executor = Native {
            client: self,
            operation: &mut operation,
            preparation_timeout: request.timeout,
            send: crate::send::Options {
                plan: request.route.clone(),
                ..Default::default()
            },
            collection: request.collection.clone(),
        };
        run(
            &request,
            &self.registry,
            &mut deadline,
            &mut clock,
            &mut authorizer,
            &mut executor,
            publish,
        )
    }
}

pub(super) fn run<A, E, C, F>(
    request: &Request,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
    clock: &mut C,
    authorizer: &mut A,
    executor: &mut E,
    mut publish: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: OsExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let started = clock.now();
    request.validate()?;
    deadline.enforce()?;
    let (selected, ()) = admit_operation(
        authorizer,
        deadline,
        probe_error,
        &request.target,
        FamilyGate::new(Family::Any, |_| {
            Error::Invalid("no numeric target selected".into())
        }),
        |_| Ok(()),
        |_| {
            Ok(wire_limits(
                request.limits.max_probes as u64,
                request.limits.max_probes as u64 * super::MAX_WIRE_BYTES,
            ))
        },
    )?;
    let target = selected
        .targets
        .first()
        .ok_or_else(|| Error::Invalid("no selected target".into()))?;
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|source| Error::Execution {
        sequence: 0,
        source: super::executor::failure(source),
    })?;
    let base_identity = u32::from_be_bytes(entropy[..4].try_into().expect("four entropy bytes"));
    let source_port =
        49152 + u16::from_be_bytes(entropy[4..6].try_into().expect("two entropy bytes")) % 16384;
    let base = PlannedProbe {
        sequence: 1,
        attempt: 1,
        address: target.address,
        interface: target.interface().cloned(),
        port: request.open_port,
        source_port,
        identity: base_identity,
        kind: Some(Probe::OpenSyn),
        cleanup_ack: 0,
    };
    let preparation = executor.prepare(&base, deadline);
    // Expiry/cancellation observed during preparation outranks its timeout or
    // provider error, just as it does during a planned probe exchange.
    deadline.enforce()?;
    let preparation = preparation.map_err(|source| Error::Execution {
        sequence: 0,
        source,
    })?;
    // Resolution elapsed time includes pre-send setup. Without its send
    // timestamp, conservatively owe a full rate interval from completion;
    // run_planned accounts for the shared deadline before sleeping.
    let paced_after = (preparation.stats.packets_completed > 0).then(|| clock.now());
    let preparation_frames = preparation.captured.len();
    let preparation_bytes = preparation
        .captured
        .iter()
        .try_fold(0_usize, |sum, frame| sum.checked_add(frame.bytes().len()))
        .ok_or_else(|| Error::Invalid("neighbor evidence byte overflow".into()))?;
    if preparation_frames > request.limits.evidence.max_frames
        || preparation_bytes > request.limits.evidence.max_bytes
    {
        return Err(Error::Invalid(
            "neighbor capture exceeds operation evidence budget".into(),
        ));
    }
    let mut internal = Collector::default();
    let prep_stats = preparation.stats.clone();
    if preparation.request_bytes.is_some() || preparation_frames > 0 {
        let event = Event::Preparation(preparation);
        internal.publish(event.clone()).map_err(Error::Output)?;
        publish(event, deadline)?;
    }
    let mut limits = request.limits.evidence;
    limits.max_frames -= preparation_frames;
    limits.max_bytes -= preparation_bytes;
    let state = internal.clone();
    let mut evidence = BatchEvidence::new_with_retention_limits(
        Workflow::Os,
        probe_error,
        request.limits.evidence,
        limits,
        Fingerprints {
            registry,
            pending_cleanup: None,
        },
        |event: Event, deadline: &Deadline| {
            internal.publish(event.clone()).map_err(Error::Output)?;
            publish(event, deadline)
        },
    );
    let mut phase = 0_usize;
    let mut attempt = 1_u32;
    let mut sequence = 0_u64;
    let kinds = [
        Probe::OpenSyn,
        Probe::ClosedSyn,
        Probe::TimestampSyn,
        Probe::Echo,
    ];
    let mut planned = |evidence: &mut BatchEvidence<Fingerprints<'_>, _, _>,
                       _: std::time::Instant,
                       _: &Deadline| {
        if let Some(mut cleanup) = evidence.classifier_mut().pending_cleanup.take() {
            sequence += 1;
            cleanup.sequence = sequence;
            return Ok(Some(Batch {
                probes: vec![cleanup],
                timeout: request.timeout,
                sequence,
                permit: crate::evidence::ExecutionPermit::new(),
            }));
        }
        if phase >= kinds.len() {
            return Ok(None);
        }
        if phase == 2 && attempt == 1 {
            let observations = state.observations();
            for kind in [Probe::OpenSyn, Probe::ClosedSyn] {
                let flags = if kind == Probe::ClosedSyn { 0x14 } else { 0x12 };
                if !observations
                    .iter()
                    .any(|observation| observation.probe == kind)
                    || !observations
                        .iter()
                        .filter(|observation| observation.probe == kind)
                        .all(|observation| {
                            observation.suitable
                                && observation
                                    .tcp
                                    .as_ref()
                                    .is_some_and(|tcp| tcp.flags == flags)
                        })
                {
                    return Ok(None);
                }
            }
        }
        let kind = kinds[phase];
        sequence += 1;
        let probe = PlannedProbe {
            sequence,
            attempt,
            kind: Some(kind),
            port: if kind == Probe::ClosedSyn {
                request.closed_port
            } else {
                request.open_port
            },
            identity: base_identity.wrapping_add(sequence as u32),
            ..base.clone()
        };
        attempt += 1;
        if attempt > request.attempts {
            phase += 1;
            attempt = 1;
        }
        Ok(Some(Batch {
            probes: vec![probe],
            timeout: request.timeout,
            sequence,
            permit: crate::evidence::ExecutionPermit::new(),
        }))
    };
    let mut stats = run_planned(
        &mut planned,
        Some(request.probes_per_second),
        paced_after,
        deadline,
        clock,
        executor,
        &mut evidence,
    )?;
    let retained_evidence_bytes = evidence.retained_evidence_bytes() + preparation_bytes;
    drop(evidence);
    stats.checked_add_assign(&prep_stats).map_err(|source| {
        (probe_error)(sequence, crate::execution::Failure::StatsOverflow(source))
    })?;
    let observations = state.observations();
    let complete = !state.incomplete();
    let identification = if complete {
        core::evaluate(&request.corpus, &observations)?
    } else {
        Match {
            outcome: Outcome::Inconclusive,
            reason: "fingerprint evidence retention was exhausted".into(),
            candidates: Vec::new(),
        }
    };
    deadline.enforce()?;
    stats.elapsed = stats
        .elapsed
        .max(clock.now().saturating_duration_since(started));
    Ok(Report {
        target: request.target.clone(),
        probe_set: core::PROBE_SET_V1,
        corpus: request.corpus.name.clone(),
        corpus_version: request.corpus.version.clone(),
        identification,
        observations,
        retained_evidence_bytes,
        complete,
        stats,
    })
}
