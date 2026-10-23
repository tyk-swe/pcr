// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{packet::Probe, topology::Topology, *};
use crate::traceroute::{Error, ResponseKind, Termination, error::probe_error};
use crate::{
    Client, Sink, Stats,
    clock::Clock,
    engine::{
        admission::{FamilyGate, admit_operation, wire_limits},
        execution::{Context, Grant, Operation, publisher, rate_delay},
    },
    evidence::RetentionBudget,
    policy::Authorizer,
    probe::{
        Transport,
        runner::{Evidence, validate_batch_evidence},
    },
    providers::{PacketProviders, TargetProviders},
    target::ResolveTarget,
};
use packetcraftr_core::{
    budget::Deadline, diagnostic::Diagnostic, error::BoundaryError, registry::Registry,
};
use std::collections::BTreeSet;

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

struct Native<'a, P, K> {
    client: &'a Client<P, K>,
    operation: &'a Operation,
    send: crate::send::Options,
    collection: crate::exchange::Collection,
    strategy: Transport,
    pinned: Option<crate::route::Plan>,
}

impl<P: PacketProviders, K: Clock> Runner for Native<'_, P, K> {
    fn exchange(
        &mut self,
        probes: &[Probe],
        grant: Grant,
        spent: &Stats,
    ) -> Result<Evidence, BoundaryError> {
        let mut operation = self.operation.clone();
        operation.spent = spent.clone();
        let mut matcher =
            |_: usize,
             sent: &packetcraftr_core::packet::Packet,
             received: &packetcraftr_core::decode::DecodedPacket| {
                packet::classify(&operation.registry, self.strategy, sent, received).is_some()
            };
        self.client
            .exchange_packets(
                probes.iter().map(|probe| probe.packet.clone()).collect(),
                &self.send,
                grant.timeout,
                self.collection.clone(),
                &operation,
                &mut matcher,
                &mut self.pinned,
            )
            .map(|result| Evidence::from_exchange(grant.permit, result))
            .map_err(BoundaryError::from_error)
    }

    fn cleanup(&mut self, evidence: &Evidence, spent: &Stats) -> Result<Stats, BoundaryError> {
        if self.strategy != Transport::Tcp {
            return Ok(Stats::default());
        }
        let mut resets = Vec::new();
        let mut seen = BTreeSet::new();
        for response in &evidence.responses {
            if seen.contains(&response.request_index) {
                continue;
            }
            if let Some(reset) = packet::reset(
                &evidence.sent[response.request_index].built().packet,
                &response.response,
            ) {
                seen.insert(response.request_index);
                resets.push(reset);
            }
        }
        if resets.is_empty() {
            return Ok(Stats::default());
        }
        let started = self.client.clock.now();
        let mut operation = self.operation.clone();
        operation.spent = spent.clone();
        let mut stream = self
            .client
            .streaming_in(&self.send, resets.len() as u64, &operation)
            .map_err(BoundaryError::from_error)?;
        let mut stats = Stats::default();
        for reset in resets {
            let prepared = stream.prepare(reset).map_err(BoundaryError::from_error)?;
            if let Some(expected) = &self.pinned {
                let actual = &prepared.route().plan;
                if actual.packet_source != expected.packet_source
                    || actual.decision.interface != expected.decision.interface
                    || actual.mode != expected.mode
                {
                    return Err(BoundaryError::from_error(
                        crate::exchange::Error::HeterogeneousRoute,
                    ));
                }
            }
            let sent = stream
                .transmit(prepared)
                .map_err(BoundaryError::from_error)?;
            stats.packets_attempted += 1;
            stats.packets_completed += 1;
            stats.bytes += sent.bytes_sent() as u64;
        }
        stats.elapsed = self.client.clock.now().saturating_duration_since(started);
        Ok(stats)
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
        let mut admission =
            crate::engine::admission::Admission::new(&policy, self.providers.resolver());
        let emit = publisher(
            &operation.runtime,
            sink,
            |error| probe_error(0, crate::engine::execution::Failure::DurationLimit(error)),
            |source| Error::Output { source },
        )?;
        let mut seed = [0; 8];
        getrandom::fill(&mut seed).map_err(|error| Error::Execution {
            sequence: 0,
            source: BoundaryError::new(
                error.to_string(),
                packetcraftr_core::error::Classification::new(
                    "io.traceroute_entropy",
                    packetcraftr_core::error::Kind::Io,
                    None,
                ),
                Vec::new(),
            ),
        })?;
        run(
            &request,
            &mut admission,
            &operation.registry,
            &mut Native {
                client: self,
                operation: &operation,
                strategy: request.trace.strategy,
                pinned: None,
                collection: request.trace.collection.clone(),
                send: crate::send::Options {
                    destination: None,
                    plan: request.trace.route.clone(),
                    build: Default::default(),
                    allow_permissive_live: false,
                },
            },
            &mut self.clock.clone(),
            &mut operation.deadline(self, request.trace.limits.max_duration),
            u64::from_be_bytes(seed),
            emit,
        )
    }
}

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
    let cleanup_count = if trace.strategy == Transport::Tcp {
        usize::from(request.flows) * trace.probes_per_hop as usize
    } else {
        0
    };
    let count = request.probe_count() + cleanup_count;
    let wire_bytes = count as u64
        * (crate::traceroute::MAX_PROBE_BYTES
            + packet::MAX_IDENTITY_BYTES
            + u64::from(trace.payload_size));
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
    let mut flows = packet::flows(request, destination, nonce);
    let mut flow_summaries = flows
        .iter()
        .map(|flow| FlowSummary {
            flow_id: flow.id,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let mut destination_times = vec![Vec::new(); flows.len()];
    let mut context = Context::new(deadline, clock, probe_error);
    let mut spent = Stats::default();
    let mut budget = RetentionBudget::default();
    let mut summary = Summary {
        planned_probes: request.probe_count(),
        ..Summary::default()
    };
    let mut topology = Topology::default();
    let mut completions = Vec::new();
    let mut diagnostics = BTreeSet::new();
    let mut unmatched = 0;
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
            if summary.probes_sent == 0 {
                let source = evidence.sent[0].route().plan.packet_source;
                for flow in &mut flows {
                    flow.source = source.ok_or_else(|| Error::InvalidEvidence {
                        sequence,
                        message: "missing materialized source address".into(),
                    })?;
                    emit(Event::Flow(flow.clone()), context.deadline())?;
                }
            }
            let quality_incomplete = evidence.observation_quality
                != Some(packetcraftr_netio::capture::ObservationQuality::NoReportedLoss);
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
            summary.incomplete |= batch_incomplete;
            if quality_incomplete && diagnostics.insert("multipath.capture_quality".to_owned()) {
                emit(
                    Event::Diagnostic(Diagnostic::warning(
                        "multipath.capture_quality",
                        "local capture completeness is unavailable or reports loss; silence is not forwarding loss",
                    )),
                    context.deadline(),
                )?;
            }
            for diagnostic in &evidence.diagnostics {
                if diagnostics.insert(diagnostic.code.to_string()) {
                    emit(Event::Diagnostic(diagnostic.clone()), context.deadline())?;
                }
            }
            for (index, probe) in probes.iter().enumerate() {
                context.enforce(probe.sequence)?;
                let flow_index = usize::from(probe.flow.id - 1);
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
                    incomplete: batch_incomplete,
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
                    } else if classification.kind == ResponseKind::Unreachable && terminal.is_none()
                    {
                        terminal = Some(Termination::Unreachable);
                    }
                    let frame = &response.response.frame;
                    if budget
                        .reserve(
                            frame.bytes().len().saturating_add(METADATA_BYTES),
                            trace.limits.evidence.max_frames,
                            trace.limits.evidence.max_bytes,
                        )
                        .is_ok()
                    {
                        record.replies.push(Reply {
                            responder: classification.responder,
                            kind: classification.kind,
                            latency: response.latency,
                            frame: frame.clone(),
                        });
                    } else {
                        record.incomplete = true;
                        summary.omitted_frames += 1;
                        summary.incomplete = true;
                    }
                }
                record.ambiguous = responders.len() > 1;
                summary.probes_sent += 1;
                summary.replies_seen += record.replies_seen;
                summary.ambiguous_probes += usize::from(record.ambiguous);
                if record.replies_seen == 0 {
                    summary.unanswered_probes += 1;
                } else {
                    summary.answered_probes += 1;
                    answered[flow_index] = true;
                }
                let flow_summary = &mut flow_summaries[flow_index];
                flow_summary.probes_sent += 1;
                flow_summary.answered_probes += usize::from(record.replies_seen > 0);
                flow_summary.unanswered_probes += usize::from(record.replies_seen == 0);
                flow_summary.ambiguous_probes += usize::from(record.ambiguous);
                for reply in &record.replies {
                    if reply.kind == ResponseKind::DestinationReached {
                        destination_times[flow_index].push(reply.latency);
                    }
                }
                let update = topology.observe(&record);
                emit(Event::Probe(record), context.deadline())?;
                if !update.nodes.is_empty()
                    || !update.edges.is_empty()
                    || !update.changes.is_empty()
                {
                    emit(Event::Topology(update), context.deadline())?;
                }
                if let Some(completion) = terminal.or_else(|| {
                    (hop == trace.max_hops).then_some(if answered[flow_index] {
                        Termination::MaximumHops
                    } else {
                        Termination::Timeout
                    })
                }) {
                    active[flow_index] = false;
                    if completion == Termination::DestinationReached {
                        flow_summaries[flow_index].sweeps_reached += 1;
                    }
                    let completion = FlowCompletion {
                        flow_id: probe.flow.id,
                        sweep,
                        completion,
                        last_hop: hop,
                    };
                    emit(Event::FlowComplete(completion.clone()), context.deadline())?;
                    completions.push(completion);
                }
            }
            for frame in evidence.undecoded.iter().chain(
                evidence
                    .unsolicited
                    .iter()
                    .map(|capture| &capture.decoded.frame),
            ) {
                if unmatched < trace.limits.evidence.max_undecoded
                    && budget
                        .reserve(
                            frame.bytes().len().saturating_add(METADATA_BYTES),
                            trace.limits.evidence.max_frames,
                            trace.limits.evidence.max_bytes,
                        )
                        .is_ok()
                {
                    unmatched += 1;
                    emit(
                        Event::Unmatched {
                            sweep,
                            hop_limit: hop,
                            frame: frame.clone(),
                        },
                        context.deadline(),
                    )?;
                } else {
                    summary.omitted_frames += 1;
                    summary.incomplete = true;
                }
            }
            context.enforce(sequence)?;
            let cleanup = runner
                .cleanup(&evidence, &spent)
                .map_err(|source| Error::Execution { sequence, source })?;
            context.account(sequence, &cleanup)?;
            spent
                .checked_add_assign(&cleanup)
                .map_err(|_| Error::StatisticsOverflow { sequence })?;
            summary.cleanup_packets += cleanup.packets_attempted;
        }
        summary.sweeps_completed += 1;
    }
    context.enforce(0)?;
    if summary.omitted_frames > 0 {
        emit(
            Event::Diagnostic(Diagnostic::warning(
                "multipath.evidence_limit",
                "evidence limits omitted frames; topology contains retained observations only",
            )),
            context.deadline(),
        )?;
    }
    summary.retained_evidence_bytes = budget.bytes();
    let topology = topology.finish(&mut summary);
    for (flow, mut times) in flow_summaries.iter_mut().zip(destination_times) {
        times.sort_unstable();
        if !times.is_empty() {
            flow.destination_rtt = Some(Rtt {
                samples: times.len(),
                minimum: times[0],
                median: times[(times.len() - 1) / 2],
                maximum: times[times.len() - 1],
            });
        }
    }
    Ok(Report {
        target: selected.declared.clone(),
        resolved_addresses: selected.addresses(),
        destination,
        strategy: trace.strategy,
        flows,
        flow_summaries,
        completions,
        topology,
        summary,
        stats: context.into_stats(),
    })
}
