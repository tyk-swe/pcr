// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod prepare;
use super::{Batch, Classification, SentProbe, classify_response};
use crate::{
    Client, SentPacket, Stats,
    probe::{ExchangeExecutor, Execution, PipelineEvent, PipelineOptions},
};
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    diagnostic::Diagnostic,
    error::{BoundaryError, Classification as ErrorClassification, Classified, Kind},
    frame::Frame,
};
use packetcraftr_netio::{
    capture::{self, group},
    neighbor, route, transmit,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct PendingEvidence {
    pub sent: SentProbe,
    pub response: Option<Frame>,
}
#[derive(Debug, thiserror::Error)]
#[error("packet scan pipeline failed: {source}")]
pub struct Error {
    #[source]
    pub source: BoundaryError,
    pub stats: Stats,
    pub pending: Vec<PendingEvidence>,
    pub failed_probe: Option<super::Probe>,
    pub capture_sources: Vec<group::Source>,
    pub cleanup: Option<Box<group::Error>>,
}
impl Classified for Error {
    fn classification(&self) -> ErrorClassification {
        self.source.classification()
    }
    fn causes(&self) -> Vec<String> {
        let mut causes = self.source.causes();
        if let Some(cleanup) = &self.cleanup {
            causes.push(cleanup.to_string());
            causes.extend(cleanup.causes());
        }
        causes
    }
    fn context(&self) -> Option<packetcraftr_core::error::Coordinate> {
        self.failed_probe
            .as_ref()
            .map(|probe| packetcraftr_core::error::Coordinate::ProbeSequence(probe.sequence))
            .or_else(|| self.source.context())
    }
}
#[derive(Default)]
struct EvidenceUsage {
    frames: usize,
    bytes: usize,
}
struct Pending {
    sent: Arc<SentPacket>,
    deadline: Instant,
    best: Option<crate::exchange::Response>,
    last_response: Option<Frame>,
    rank: u8,
    charge: usize,
}
/// Rejects an empty or out-of-budget pipeline configuration before any
/// resource is armed, so a scan that cannot proceed arms no capture.
fn validate_options(batches: &[Batch], options: &PipelineOptions) -> Result<(), BoundaryError> {
    if batches.is_empty()
        || batches.len() > super::MAX_PROBES
        || options.max_in_flight == 0
        || options.max_in_flight > 1024
        || options.max_prepared_bytes == 0
        || options.max_prepared_bytes > 256 * 1024 * 1024
        || options.max_evidence_frames == 0
        || options.max_evidence_bytes == 0
        || options.max_evidence_bytes > capture::MAX_CAPTURE_QUEUE_BYTES
        || options.max_evidence_frames > capture::MAX_CAPTURE_QUEUE_FRAMES
        || options
            .probes_per_second
            .is_some_and(|rate| rate == 0 || rate > super::MAX_RATE)
        || options.max_undecoded > options.max_evidence_frames
        || options.max_duration.is_zero()
        || options.max_duration > super::MAX_DURATION
    {
        return Err(limit("pipeline configuration", 1024));
    }
    Ok(())
}

/// Scores every pending probe a captured record could complete: interface,
/// freshness window, transport classification, and application evidence. An
/// empty or ambiguous result leaves the frame unattributed.
fn ranked_candidates(
    pending: &BTreeMap<usize, Pending>,
    batches: &[Batch],
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<(usize, u8, bool)> {
    let mut candidates = Vec::new();
    for (index, entry) in pending {
        if entry.sent.route().plan.decision.interface != *native_interface
            || received < entry.sent.timing().freshness_marker().monotonic()
            || received > entry.deadline
        {
            continue;
        }
        if let Some(classified) = classify_response(
            registry,
            batches[*index].probe.endpoint.transport(),
            &entry.sent.built().packet,
            decoded,
        ) {
            let application = super::profile::evidence(
                &batches[*index].probe,
                &entry.sent.built().packet,
                decoded,
            );
            let rank = classified.classification.rank() * 4
                + application
                    .as_ref()
                    .map_or(2, super::profile::Evidence::rank);
            let definitive = classified.classification == Classification::Open
                && application.as_ref().is_none_or(|evidence| {
                    matches!(
                        evidence.status,
                        super::profile::Status::Confirmed | super::profile::Status::Unchecked
                    )
                });
            candidates.push((*index, rank, definitive));
        }
    }
    candidates
}

pub(super) fn limit(field: &'static str, maximum: usize) -> BoundaryError {
    BoundaryError::new(
        format!("scan pipeline exceeds {field}={maximum}"),
        ErrorClassification::new("policy.scan_pipeline_limit", Kind::Policy, None),
        Vec::new(),
    )
}
fn check<R, N, I>(client: &Client<R, N, I>, deadline: Instant) -> Result<(), BoundaryError>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    client
        .check_cancelled()
        .map_err(BoundaryError::from_error)?;
    if Instant::now() >= deadline {
        return Err(BoundaryError::new(
            "packet scan pipeline reached the operation deadline",
            ErrorClassification::new("policy.scan_duration_limit", Kind::Policy, None),
            Vec::new(),
        ));
    }
    Ok(())
}
pub(super) fn run<R, N, I>(
    executor: &mut ExchangeExecutor<'_, R, N, I>,
    batches: &[Batch],
    options: PipelineOptions,
    emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
) -> Result<Stats, BoundaryError>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender + capture::Provider,
{
    validate_options(batches, &options)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", 3600))?;
    let plan = prepare::plan(executor, batches, options, deadline)?;
    let request = group::Request {
        interfaces: plan.interfaces.clone(),
        limits: executor.options.capture,
        filter: None,
        promiscuous: false,
        native: Default::default(),
    };
    request.validate().map_err(BoundaryError::from_error)?;
    let mut group = group::Group::arm(
        &executor.client.io,
        &request,
        executor.client.cancellation.clone(),
    )
    .map_err(BoundaryError::from_error)?;
    let mut stats = Stats::default();
    let mut inflight = InFlight {
        pending: BTreeMap::new(),
        retained: plan.base_bytes,
        evidence: EvidenceUsage::default(),
        failed_probe: None,
    };
    let result = (|| -> Result<(), BoundaryError> {
        check(executor.client, deadline)?;
        group
            .wait_ready(deadline.saturating_duration_since(Instant::now()))
            .map_err(BoundaryError::from_error)?;
        let builder = Builder::new(executor.client.registry.clone());
        let decoder = Dissector::new(executor.client.registry.clone());
        let spacing = crate::clock::rate_delay(1, options.probes_per_second)
            .ok_or_else(|| limit("probe rate", super::MAX_RATE as usize))?;
        let source_count = group.sources().len();
        let capture_drain_limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * source_count;
        let ctx = Context {
            executor,
            batches,
            plan: &plan,
            options,
            deadline,
            spacing,
            builder,
            decoder,
        };
        let mut admission = Admission::new();
        let mut drain = Drain::new(capture_drain_limit);
        let mut correlation = Correlation::default();
        while admission.next < ctx.batches.len() || !inflight.pending.is_empty() {
            check(ctx.executor.client, ctx.deadline)?;
            let draining = drain.decide(&ctx, Instant::now(), &mut inflight, emit)?;
            admission.admit(&ctx, draining, &mut inflight, &mut stats, emit)?;
            if admission.next == ctx.batches.len() && inflight.pending.is_empty() {
                break;
            }
            let mut wait = admission
                .wake(&ctx, &inflight)
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5));
            if draining {
                drain.consume();
                wait = Duration::ZERO;
            }
            let Some(record) = group.next_record(wait).map_err(BoundaryError::from_error)? else {
                if draining {
                    drain.exhaust();
                }
                continue;
            };
            correlation.record(record, &ctx, &mut inflight, emit)?;
        }
        Ok(())
    })();

    let mut cleanup = None;
    let mut result = result;
    let capture_sources = if group.shutdown_attempted() {
        group.snapshot()
    } else {
        match group.shutdown() {
            Ok(sources) => sources,
            Err(error) => {
                let sources = error.sources.clone();
                if result.is_ok() {
                    result = Err(BoundaryError::from_error(error));
                } else {
                    cleanup = Some(Box::new(error));
                }
                sources
            }
        }
    };
    for source in &capture_sources {
        if let Some(sum) = stats.capture.checked_add(source.statistics) {
            stats.capture = sum;
        } else {
            if result.is_ok() {
                result = Err(limit("capture statistics", usize::MAX));
            }
            break;
        }
    }
    stats.elapsed = started.elapsed();
    let result = result.and_then(|()| {
        for source in &capture_sources {
            if let Some(loss) = source.statistics.evidence_loss_error() {
                if source.limits.overflow_policy == capture::OverflowPolicy::Fail {
                    return Err(BoundaryError::from_error(loss));
                }
                emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "capture.evidence_incomplete",
                    format!("source {}: {loss}", source.index),
                )))?;
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => Ok(stats),
        Err(source) => Err(BoundaryError::from_error(Error {
            source,
            stats,
            pending: pending_evidence(&inflight.pending, batches),
            failed_probe: inflight.failed_probe,
            capture_sources,
            cleanup,
        })),
    }
}
/// Read-only context the pipeline phases share for one run: the batches and
/// executor under work, their computed plan, and the options, pacing, and
/// codecs that bound admission and correlation.
struct Context<'a, R, N, I> {
    executor: &'a ExchangeExecutor<'a, R, N, I>,
    batches: &'a [Batch],
    plan: &'a prepare::Plan,
    options: PipelineOptions,
    deadline: Instant,
    spacing: Duration,
    builder: Builder,
    decoder: Dissector,
}
/// The rolling in-flight window the phases share: admitted but incomplete
/// probes, the prepared bytes they retain, the evidence their best responses
/// charge, and the probe currently inside a fallible step (reported as the
/// failure coordinate).
struct InFlight {
    pending: BTreeMap<usize, Pending>,
    retained: usize,
    evidence: EvidenceUsage,
    failed_probe: Option<super::Probe>,
}
/// Rolling send-admission state: the next batch index and the pacing gate for
/// the following send.
struct Admission {
    next: usize,
    next_send: Instant,
}
impl Admission {
    fn new() -> Self {
        Self {
            next: 0,
            next_send: Instant::now(),
        }
    }
    /// Window capacity and the retained-byte ceiling admit another batch;
    /// pacing stays a separate gate so wakeups can wait on it.
    fn has_capacity<R, N, I>(&self, ctx: &Context<'_, R, N, I>, inflight: &InFlight) -> bool {
        self.next < ctx.batches.len()
            && inflight.pending.len() < ctx.options.max_in_flight
            && inflight
                .retained
                .saturating_add(ctx.plan.costs[self.next].memory)
                <= ctx.options.max_prepared_bytes
    }
    /// The next instant the loop must wake: the earliest pending deadline (or
    /// the operation deadline), pulled earlier to the pacing gate while
    /// another send could proceed.
    fn wake<R, N, I>(&self, ctx: &Context<'_, R, N, I>, inflight: &InFlight) -> Instant {
        let earliest = inflight
            .pending
            .values()
            .map(|entry| entry.deadline)
            .min()
            .unwrap_or(ctx.deadline)
            .min(ctx.deadline);
        if self.has_capacity(ctx, inflight) {
            earliest.min(self.next_send)
        } else {
            earliest
        }
    }
    /// Sends every batch the window, pacing, and byte budget currently admit.
    /// A paced admission yields the loop so captured evidence interleaves with
    /// sending.
    fn admit<R, N, I>(
        &mut self,
        ctx: &Context<'_, R, N, I>,
        draining: bool,
        inflight: &mut InFlight,
        stats: &mut Stats,
        emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<(), BoundaryError>
    where
        R: route::Provider,
        N: neighbor::Resolver,
        I: transmit::Sender,
    {
        while !draining && self.has_capacity(ctx, inflight) && Instant::now() >= self.next_send {
            self.send_next(ctx, inflight, stats, emit)?;
            if !ctx.spacing.is_zero() {
                break;
            }
        }
        Ok(())
    }
    /// Prepares, authorizes, transmits, and records `batches[next]` as pending,
    /// then advances the pacing gate.
    fn send_next<R, N, I>(
        &mut self,
        ctx: &Context<'_, R, N, I>,
        inflight: &mut InFlight,
        stats: &mut Stats,
        emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<(), BoundaryError>
    where
        R: route::Provider,
        N: neighbor::Resolver,
        I: transmit::Sender,
    {
        check(ctx.executor.client, ctx.deadline)?;
        let batch = &ctx.batches[self.next];
        inflight.failed_probe = Some(batch.probe.clone());
        let planned = prepare::planned(
            ctx.executor.client,
            batch,
            ctx.plan.routes[&batch.probe.address].clone(),
            &ctx.builder,
            &ctx.executor.options.send,
            ctx.deadline,
        )?;
        if planned.preliminary_build.bytes.len() != ctx.plan.costs[self.next].wire {
            return Err(limit(
                "changed preparation size",
                ctx.plan.costs[self.next].wire,
            ));
        }
        let mut send = ctx.executor.options.send.clone();
        send.destination = Some(batch.probe.address);
        let prepared = ctx
            .executor
            .client
            .materialize_and_authorize(planned, &ctx.builder, &send, Some(ctx.deadline))
            .map_err(BoundaryError::from_error)?;
        if !super::probe::sent_probe_matches(&batch.probe, &prepared.built.packet) {
            return Err(BoundaryError::internal_execution(
                "materialized scan packet differs from its probe",
                "internal.scan_probe_mismatch",
                "preserve the planned endpoint and identity",
            ));
        }
        check(ctx.executor.client, ctx.deadline)?;
        let frame = transmit::Frame::try_new(&prepared.built.bytes, &prepared.route)
            .map_err(BoundaryError::from_error)?;
        stats.packets_attempted += 1;
        let receipt = ctx
            .executor
            .client
            .io
            .send(frame)
            .map_err(BoundaryError::from_error)?;
        let sent = Arc::new(
            SentPacket::try_new(prepared.built, prepared.route, receipt)
                .map_err(BoundaryError::from_error)?,
        );
        stats.packets_completed += 1;
        stats.bytes = stats
            .bytes
            .checked_add(sent.bytes_sent() as u64)
            .ok_or_else(|| limit("sent bytes", usize::MAX))?;
        let end = sent
            .timing()
            .freshness_marker()
            .monotonic()
            .checked_add(batch.timeout)
            .ok_or_else(|| limit("probe timeout", 3600))?
            .min(ctx.deadline);
        inflight.pending.insert(
            self.next,
            Pending {
                sent: sent.clone(),
                deadline: end,
                best: None,
                last_response: None,
                rank: 0,
                charge: ctx.plan.costs[self.next].memory,
            },
        );
        inflight.retained += ctx.plan.costs[self.next].memory;
        emit(PipelineEvent::Sent {
            index: self.next,
            sent,
        })?;
        inflight.failed_probe = None;
        self.next += 1;
        self.next_send = Instant::now()
            .checked_add(ctx.spacing)
            .ok_or_else(|| limit("pacing delay", 3600))?;
        Ok(())
    }
}
/// Capture-drain fairness state: the cohort of expired probes whose queued
/// replies may still arrive, and the rotations that cohort may still consume.
struct Drain {
    cohort: HashSet<usize>,
    remaining: usize,
    limit: usize,
}
impl Drain {
    fn new(limit: usize) -> Self {
        Self {
            cohort: HashSet::new(),
            remaining: limit,
            limit,
        }
    }
    /// Splits the iteration's expired pendings: while their cohort still holds
    /// drain rotations the loop keeps rotating captures for them, otherwise
    /// they complete now and the cohort resets. Returns whether sending must
    /// yield to draining.
    fn decide<R, N, I>(
        &mut self,
        ctx: &Context<'_, R, N, I>,
        now: Instant,
        inflight: &mut InFlight,
        emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<bool, BoundaryError> {
        let expired: Vec<_> = inflight
            .pending
            .iter()
            .filter(|(_, entry): &(&usize, &Pending)| now >= entry.deadline)
            .map(|(index, _)| *index)
            .collect();
        let cohort_len = self.cohort.len();
        self.cohort.extend(expired.iter().copied());
        if self.cohort.len() > cohort_len {
            self.remaining = self.limit;
        }
        // A callback can consume the rest of another probe's timeout after
        // its reply has already entered a capture queue. Give each expired
        // cohort enough fair rotations to reach every record that could
        // occupy the partitioned queues, even if newer traffic refills
        // slots. Correlation below still enforces each ingress deadline.
        let draining = !expired.is_empty() && self.remaining > 0;
        if !draining {
            if !expired.is_empty() {
                for index in expired {
                    complete(index, ctx.batches, inflight, emit)?;
                }
            }
            self.cohort.clear();
            self.remaining = self.limit;
        }
        Ok(draining)
    }
    /// One rotation was spent waiting for the draining cohort's records.
    fn consume(&mut self) {
        self.remaining -= 1;
    }
    /// The capture group reported no further record for the cohort.
    fn exhaust(&mut self) {
        self.remaining = 0;
    }
}
/// Record-correlation state: captured-frame dedup, the undecoded-emission
/// budget, and one-shot diagnostics shared by the decode verdicts.
#[derive(Default)]
struct Correlation {
    seen: HashSet<capture::RecordIdentity>,
    seen_order: VecDeque<capture::RecordIdentity>,
    undecoded: usize,
    diagnostics: HashSet<&'static str>,
}
impl Correlation {
    /// Attributes one captured record to a pending probe: dedup, decode,
    /// integrity, and ingress checks, candidate ranking, evidence retention,
    /// and completion on a definitive verdict.
    fn record<R, N, I>(
        &mut self,
        record: group::Record,
        ctx: &Context<'_, R, N, I>,
        inflight: &mut InFlight,
        emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    ) -> Result<(), BoundaryError> {
        if !self.seen.insert(record.captured.identity()) {
            return Ok(());
        }
        self.seen_order.push_back(record.captured.identity());
        if self.seen_order.len() > ctx.options.max_evidence_frames
            && let Some(old) = self.seen_order.pop_front()
        {
            self.seen.remove(&old);
        }
        let captured = record.captured;
        let raw = captured.frame.clone();
        let decoded = match ctx
            .decoder
            .decode(captured.frame, ctx.executor.options.decode.clone())
        {
            Ok(decoded) => decoded,
            Err(error) => {
                if self.diagnostics.insert("decode") {
                    emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.decode_error",
                        error.to_string(),
                    )))?;
                }
                if self.undecoded < ctx.options.max_undecoded {
                    emit(PipelineEvent::Undecoded { frame: raw })?;
                    self.undecoded += 1;
                }
                return Ok(());
            }
        };
        if decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            if self.diagnostics.insert("integrity") {
                emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.integrity_rejected",
                    "checksum-invalid capture was not correlated",
                )))?;
            }
            return Ok(());
        }
        let Some(received) = captured.received_at else {
            if self.diagnostics.insert("ingress") {
                emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "capture lacks a monotonic ingress marker and was not correlated",
                )))?;
            }
            return Ok(());
        };
        let candidates = ranked_candidates(
            &inflight.pending,
            ctx.batches,
            &ctx.executor.client.registry,
            &decoded,
            &ctx.plan.interfaces[record.source],
            received,
        );
        if candidates.len() != 1 {
            if candidates.len() > 1 && self.diagnostics.insert("ambiguous") {
                emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.ambiguous_response",
                    "capture matched multiple pending probes and was not attributed",
                )))?;
            }
            return Ok(());
        }
        let (index, rank, definitive) = candidates[0];
        let entry = inflight
            .pending
            .get_mut(&index)
            .expect("candidate is pending");
        if entry.best.is_none() || rank > entry.rank {
            if let Some(previous) = &entry.best {
                inflight.evidence.frames -= 1;
                inflight.evidence.bytes -= previous.response.frame.bytes().len();
            }
            retain(raw.bytes().len(), &mut inflight.evidence, ctx.options)?;
            entry.rank = rank;
            entry.best = Some(crate::exchange::Response {
                request_index: 0,
                response: decoded,
                latency: received
                    .duration_since(entry.sent.timing().freshness_marker().monotonic()),
            });
        }
        if definitive {
            complete(index, ctx.batches, inflight, emit)?;
        }
        Ok(())
    }
}
fn retain(
    bytes: usize,
    usage: &mut EvidenceUsage,
    options: PipelineOptions,
) -> Result<(), BoundaryError> {
    usage.frames = usage
        .frames
        .checked_add(1)
        .filter(|count| *count <= options.max_evidence_frames)
        .ok_or_else(|| limit("evidence frames", options.max_evidence_frames))?;
    usage.bytes = usage
        .bytes
        .checked_add(bytes)
        .filter(|count| *count <= options.max_evidence_bytes)
        .ok_or_else(|| limit("evidence bytes", options.max_evidence_bytes))?;
    Ok(())
}
fn complete(
    index: usize,
    batches: &[Batch],
    inflight: &mut InFlight,
    emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
) -> Result<(), BoundaryError> {
    let entry = inflight
        .pending
        .get_mut(&index)
        .expect("completed pending probe");
    entry.last_response = entry
        .best
        .as_ref()
        .map(|response| response.response.frame.clone());
    inflight.failed_probe = Some(batches[index].probe.clone());
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: entry.sent.bytes_sent() as u64,
        elapsed: entry.sent.timing().freshness_marker().monotonic().elapsed(),
        capture: Default::default(),
    };
    let execution = Execution {
        permit: batches[index].permit,
        sent: vec![entry.sent.as_ref().clone()],
        responses: entry.best.take().into_iter().collect(),
        unsolicited: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats,
    };
    emit(PipelineEvent::Completed { index, execution })?;
    let entry = inflight
        .pending
        .remove(&index)
        .expect("completed pending probe");
    inflight.retained -= entry.charge;
    if let Some(response) = entry.last_response {
        inflight.evidence.frames -= 1;
        inflight.evidence.bytes -= response.bytes().len();
    }
    inflight.failed_probe = None;
    Ok(())
}
fn pending_evidence(pending: &BTreeMap<usize, Pending>, batches: &[Batch]) -> Vec<PendingEvidence> {
    pending
        .iter()
        .map(|(index, entry)| PendingEvidence {
            sent: SentProbe {
                probe: batches[*index].probe.clone(),
                sent: entry.sent.clone(),
            },
            response: entry
                .best
                .as_ref()
                .map(|response| response.response.frame.clone())
                .or_else(|| entry.last_response.clone()),
        })
        .collect()
}
