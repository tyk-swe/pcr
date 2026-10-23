// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Event, Flow, FlowCompletion, FlowSummary, ProbeEvidence, Reply, Report, Request, Rtt, Summary,
    Unmatched, packet, packet::Probe, topology::Topology,
};
use crate::traceroute::{Error, MAX_PROBE_BYTES, ResponseKind, Termination, error::probe_error};
use crate::{
    Client, Sink, Stats,
    clock::Clock,
    engine::{
        admission::{Admission, FamilyGate, admit_operation, wire_limits},
        execution::{Context, Failure, Grant, Operation, publisher, rate_delay},
    },
    evidence::{Limits, RetentionBudget},
    policy::Authorizer,
    probe::{
        Transport,
        runner::{Evidence, validate_batch_evidence},
    },
    providers::{PacketProviders, TargetProviders},
    target::ResolveTarget,
};
use packetcraftr_core::{
    budget::Deadline,
    diagnostic::Diagnostic,
    error::{BoundaryError, Classification, Kind},
    frame::Frame,
    registry::Registry,
};
use packetcraftr_netio::capture::ObservationQuality;
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

// Covers retained Rust metadata, RTT samples, topology links and their evidence
// references in addition to exact captured bytes. No frame is silently evicted.
const METADATA_BYTES: usize = 2048;

pub(super) trait Runner {
    fn exchange(
        &mut self,
        probes: &[Probe],
        grant: Grant,
        spent: &Stats,
    ) -> Result<Evidence, BoundaryError>;
    fn cleanup(&mut self, _evidence: &Evidence, _spent: &Stats) -> Result<Stats, BoundaryError> {
        Ok(Stats::default())
    }
}

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    pub fn traceroute_multipath<S: Sink<Event, Ack = ()>>(
        &self,
        request: Request,
        sink: S,
    ) -> Result<Report, Error> {
        let operation = Operation::new(self, request.trace.limits.max_duration);
        let policy = operation.policy(&self.policy);
        let mut admission = Admission::new(&policy, self.providers.resolver());
        let emit = publisher(
            &operation.runtime,
            sink,
            |error| probe_error(0, Failure::DurationLimit(error)),
            |source| Error::Output { source },
        )?;
        let nonce = nonce()?;
        run(
            &request,
            &mut admission,
            &operation.registry,
            &mut super::executor::ClientRunner::new(self, &operation, &request.trace),
            &mut self.clock.clone(),
            &mut operation.deadline(self, request.trace.limits.max_duration),
            nonce,
            emit,
        )
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) fn run<A: Authorizer + ResolveTarget, R: Runner, C: Clock>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    runner: &mut R,
    clock: &mut C,
    deadline: &mut Deadline,
    nonce: u64,
    mut emit: impl FnMut(Event, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    request.validate()?;
    let trace = &request.trace;
    let approved = approve(request, authorizer, deadline)?;
    let destination = approved.destination;
    let mut flows = packet::flows(request, destination, nonce);
    let mut state = RunState::new(request, &flows);
    let mut context = Context::new(deadline, clock, probe_error);
    let mut spent = Stats::default();
    let mut previous_count = None;
    for sweep in 1..=trace.probes_per_hop {
        let mut active = vec![true; flows.len()];
        let mut answered = vec![false; flows.len()];
        for hop in trace.first_hop..=trace.max_hops {
            if !active.iter().any(|active| *active) {
                break;
            }
            let probes = flows
                .iter()
                .filter(|flow| active[usize::from(flow.id - 1)])
                .map(|flow| Probe::new(request, flow.clone(), destination, nonce, sweep, hop))
                .collect::<Vec<_>>();
            let sequence = probes[0].sequence;
            if let Some(previous) = previous_count {
                context.pace(
                    sequence,
                    rate_delay(
                        probe_error,
                        "probes_per_second",
                        previous,
                        trace.probes_per_second,
                    )?,
                )?;
            }
            previous_count = Some(probes.len());
            let (evidence, _) = context.step(
                sequence,
                trace.timeout,
                runner,
                |runner, grant| runner.exchange(&probes, grant, &spent),
                |_, evidence, grant, _| {
                    validate_batch_evidence(
                        probe_error,
                        &probes,
                        grant.timeout,
                        evidence,
                        trace.limits.evidence,
                        packet::sent_matches,
                    )
                },
            )?;
            spent
                .checked_add_assign(&evidence.stats)
                .map_err(|_| Error::StatisticsOverflow { sequence })?;
            if state.summary.probes_sent == 0 {
                let source = evidence.sent[0].route().plan.packet_source;
                for flow in &mut flows {
                    flow.source = source.ok_or_else(|| Error::InvalidEvidence {
                        sequence,
                        message: "missing materialized source address".into(),
                    })?;
                    emit(Event::Flow(flow.clone()), context.deadline())?;
                }
            }
            let batch_incomplete = state.assess(&evidence, &mut emit, context.deadline())?;
            for (index, probe) in probes.iter().enumerate() {
                context.enforce(probe.sequence)?;
                let flow_index = usize::from(probe.flow.id - 1);
                let (record, terminal) =
                    state.record(registry, trace, probe, index, &evidence, batch_incomplete)?;
                if record.replies_seen > 0 {
                    answered[flow_index] = true;
                }
                let update = state.topology.observe(&record);
                emit(Event::Probe(record), context.deadline())?;
                if !update.is_empty() {
                    emit(Event::Topology(update), context.deadline())?;
                }
                if let Some(completion) =
                    completion(terminal, hop == trace.max_hops, answered[flow_index])
                {
                    active[flow_index] = false;
                    let completion = state.complete(probe.flow.id, sweep, hop, completion);
                    emit(Event::FlowComplete(completion), context.deadline())?;
                }
            }
            state.retain_unmatched(
                &evidence,
                sweep,
                hop,
                &trace.limits.evidence,
                &mut emit,
                context.deadline(),
            )?;
            context.enforce(sequence)?;
            let cleanup = runner
                .cleanup(&evidence, &spent)
                .map_err(|source| Error::Execution { sequence, source })?;
            context.account(sequence, &cleanup)?;
            spent
                .checked_add_assign(&cleanup)
                .map_err(|_| Error::StatisticsOverflow { sequence })?;
            state.summary.cleanup_packets += cleanup.packets_attempted;
        }
        state.summary.sweeps_completed += 1;
    }
    context.enforce(0)?;
    if state.summary.omitted_frames > 0 {
        emit(
            Event::Diagnostic(Diagnostic::warning(
                "multipath.evidence_limit",
                "evidence limits omitted frames; topology contains retained observations only",
            )),
            context.deadline(),
        )?;
    }
    Ok(state.finish(approved, trace.strategy, flows, context.into_stats()))
}

fn nonce() -> Result<u64, Error> {
    let mut seed = [0; 8];
    getrandom::fill(&mut seed).map_err(|error| Error::Execution {
        sequence: 0,
        source: BoundaryError::new(
            error.to_string(),
            Classification::new("io.traceroute_entropy", Kind::Io, None),
            Vec::new(),
        ),
    })?;
    Ok(u64::from_be_bytes(seed))
}

struct Approved {
    declared: String,
    resolved_addresses: Vec<IpAddr>,
    destination: IpAddr,
}

fn approve<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<Approved, Error> {
    let trace = &request.trace;
    let cleanup_count = if trace.strategy == Transport::Tcp {
        usize::from(request.flows) * trace.probes_per_hop as usize
    } else {
        0
    };
    let count = request.probe_count() + cleanup_count;
    let wire_bytes = count as u64
        * (MAX_PROBE_BYTES + packet::MAX_IDENTITY_BYTES + u64::from(trace.payload_size));
    let (selected, _) = admit_operation(
        authorizer,
        deadline,
        probe_error,
        &trace.target,
        FamilyGate::new(trace.address_family, Error::family),
        |selected| {
            if selected.targets.iter().any(|target| target.scope.is_some()) {
                return Err(Error::ScopedTarget {
                    target: selected.declared.clone(),
                });
            }
            if trace.dont_fragment
                && selected
                    .targets
                    .first()
                    .is_some_and(|target| target.address.is_ipv6())
            {
                return Err(Error::InvalidProbeOption {
                    option: "dont_fragment",
                    reason: "IPv6 has no Don't Fragment flag".into(),
                });
            }
            Ok(())
        },
        |_| Ok(wire_limits(count as u64, wire_bytes)),
    )?;
    let destination = selected.targets[0].address;
    let resolved_addresses = selected.addresses();
    Ok(Approved {
        declared: selected.declared,
        resolved_addresses,
        destination,
    })
}

struct RunState {
    summary: Summary,
    flow_summaries: Vec<FlowSummary>,
    destination_times: Vec<Vec<Duration>>,
    topology: Topology,
    completions: Vec<FlowCompletion>,
    diagnostics: BTreeSet<String>,
    budget: RetentionBudget,
    unmatched: usize,
}

impl RunState {
    fn new(request: &Request, flows: &[Flow]) -> Self {
        Self {
            summary: Summary {
                planned_probes: request.probe_count(),
                ..Summary::default()
            },
            flow_summaries: flows
                .iter()
                .map(|flow| FlowSummary {
                    flow_id: flow.id,
                    ..Default::default()
                })
                .collect(),
            destination_times: vec![Vec::new(); flows.len()],
            topology: Topology::default(),
            completions: Vec::new(),
            diagnostics: BTreeSet::new(),
            budget: RetentionBudget::default(),
            unmatched: 0,
        }
    }

    fn retain(&mut self, frame: &Frame, limits: &Limits) -> bool {
        self.budget
            .reserve(
                frame.bytes().len().saturating_add(METADATA_BYTES),
                limits.max_frames,
                limits.max_bytes,
            )
            .is_ok()
    }

    fn assess(
        &mut self,
        evidence: &Evidence,
        emit: &mut impl FnMut(Event, &Deadline) -> Result<(), Error>,
        deadline: &Deadline,
    ) -> Result<bool, Error> {
        let quality_incomplete =
            evidence.observation_quality != Some(ObservationQuality::NoReportedLoss);
        // Unfinished correlation can hide another responder for any probe
        // in the batch, even when the capture backend reports no loss.
        let correlation_incomplete = evidence
            .unsolicited
            .iter()
            .any(|capture| capture.correlation_expired)
            || evidence
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "exchange.correlation_deadline");
        let batch_incomplete = quality_incomplete || correlation_incomplete;
        self.summary.incomplete |= batch_incomplete;
        if quality_incomplete
            && self
                .diagnostics
                .insert("multipath.capture_quality".to_owned())
        {
            emit(
                Event::Diagnostic(Diagnostic::warning(
                    "multipath.capture_quality",
                    "local capture completeness is unavailable or reports loss; silence is not forwarding loss",
                )),
                deadline,
            )?;
        }
        for diagnostic in &evidence.diagnostics {
            if self.diagnostics.insert(diagnostic.code.to_string()) {
                emit(Event::Diagnostic(diagnostic.clone()), deadline)?;
            }
        }
        Ok(batch_incomplete)
    }

    fn record(
        &mut self,
        registry: &Registry,
        trace: &crate::traceroute::Request,
        probe: &Probe,
        index: usize,
        evidence: &Evidence,
        incomplete: bool,
    ) -> Result<(ProbeEvidence, Option<Termination>), Error> {
        let mut record = ProbeEvidence {
            sequence: probe.sequence,
            flow_id: probe.flow.id,
            sweep: probe.sweep,
            hop_limit: probe.hop,
            sent_at: evidence.sent[index]
                .timing()
                .freshness_marker()
                .wall_clock(),
            replies_seen: 0,
            ambiguous: false,
            incomplete,
            replies: Vec::new(),
        };
        let mut responders = BTreeSet::new();
        let mut terminal = None;
        for response in evidence
            .responses
            .iter()
            .filter(|response| response.request_index == index)
        {
            let classification = packet::classify(
                registry,
                trace.strategy,
                &evidence.sent[index].built().packet,
                &response.response,
            )
            .ok_or_else(|| Error::InvalidEvidence {
                sequence: probe.sequence,
                message: "response failed multipath identity validation".into(),
            })?;
            record.replies_seen += 1;
            responders.insert(classification.responder);
            if classification.kind == ResponseKind::DestinationReached {
                terminal = Some(Termination::DestinationReached);
            } else if classification.kind == ResponseKind::Unreachable && terminal.is_none() {
                terminal = Some(Termination::Unreachable);
            }
            let frame = &response.response.frame;
            if self.retain(frame, &trace.limits.evidence) {
                record.replies.push(Reply {
                    responder: classification.responder,
                    kind: classification.kind,
                    latency: response.latency,
                    frame: frame.clone(),
                });
            } else {
                record.incomplete = true;
                self.summary.omitted_frames += 1;
                self.summary.incomplete = true;
            }
        }
        record.ambiguous = responders.len() > 1;
        self.summary.probes_sent += 1;
        self.summary.replies_seen += record.replies_seen;
        self.summary.ambiguous_probes += usize::from(record.ambiguous);
        if record.replies_seen == 0 {
            self.summary.unanswered_probes += 1;
        } else {
            self.summary.answered_probes += 1;
        }
        let flow_index = usize::from(probe.flow.id - 1);
        let flow_summary = &mut self.flow_summaries[flow_index];
        flow_summary.probes_sent += 1;
        flow_summary.answered_probes += usize::from(record.replies_seen > 0);
        flow_summary.unanswered_probes += usize::from(record.replies_seen == 0);
        flow_summary.ambiguous_probes += usize::from(record.ambiguous);
        for reply in &record.replies {
            if reply.kind == ResponseKind::DestinationReached {
                self.destination_times[flow_index].push(reply.latency);
            }
        }
        Ok((record, terminal))
    }

    fn complete(
        &mut self,
        flow_id: u16,
        sweep: u32,
        last_hop: u8,
        completion: Termination,
    ) -> FlowCompletion {
        if completion == Termination::DestinationReached {
            self.flow_summaries[usize::from(flow_id - 1)].sweeps_reached += 1;
        }
        let completion = FlowCompletion {
            flow_id,
            sweep,
            completion,
            last_hop,
        };
        self.completions.push(completion.clone());
        completion
    }

    fn retain_unmatched(
        &mut self,
        evidence: &Evidence,
        sweep: u32,
        hop_limit: u8,
        limits: &Limits,
        emit: &mut impl FnMut(Event, &Deadline) -> Result<(), Error>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        for frame in evidence.undecoded.iter().chain(
            evidence
                .unsolicited
                .iter()
                .map(|capture| &capture.decoded.frame),
        ) {
            if self.unmatched < limits.max_undecoded && self.retain(frame, limits) {
                self.unmatched += 1;
                emit(
                    Event::Unmatched(Unmatched {
                        sweep,
                        hop_limit,
                        frame: frame.clone(),
                    }),
                    deadline,
                )?;
            } else {
                self.summary.omitted_frames += 1;
                self.summary.incomplete = true;
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        approved: Approved,
        strategy: Transport,
        flows: Vec<Flow>,
        stats: Stats,
    ) -> Report {
        self.summary.retained_evidence_bytes = self.budget.bytes();
        let topology = self.topology.finish(&mut self.summary);
        for (flow, mut times) in self.flow_summaries.iter_mut().zip(self.destination_times) {
            times.sort_unstable();
            flow.destination_rtt = Rtt::from_sorted(&times);
        }
        Report {
            target: approved.declared,
            resolved_addresses: approved.resolved_addresses,
            destination: approved.destination,
            strategy,
            flows,
            flow_summaries: self.flow_summaries,
            completions: self.completions,
            topology,
            summary: self.summary,
            stats,
        }
    }
}

fn completion(
    terminal: Option<Termination>,
    last_hop: bool,
    answered: bool,
) -> Option<Termination> {
    terminal.or_else(|| {
        last_hop.then_some(if answered {
            Termination::MaximumHops
        } else {
            Termination::Timeout
        })
    })
}
