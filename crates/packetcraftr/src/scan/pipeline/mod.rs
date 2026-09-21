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
    let mut pending = BTreeMap::new();
    let mut failed_probe = None;
    let mut evidence = EvidenceUsage::default();
    let mut undecoded = 0usize;
    let mut seen = HashSet::new();
    let mut seen_order = VecDeque::new();
    let mut diagnostics = HashSet::new();
    let result = (|| -> Result<(), BoundaryError> {
        check(executor.client, deadline)?;
        group
            .wait_ready(deadline.saturating_duration_since(Instant::now()))
            .map_err(BoundaryError::from_error)?;
        let builder = Builder::new(executor.client.registry.clone());
        let decoder = Dissector::new(executor.client.registry.clone());
        let spacing = crate::clock::rate_delay(1, options.probes_per_second)
            .ok_or_else(|| limit("probe rate", super::MAX_RATE as usize))?;
        let mut next = 0usize;
        let mut next_send = Instant::now();
        let mut retained = plan.base_bytes;
        let source_count = group.sources().len();
        let capture_drain_limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * source_count;
        let mut capture_drain_remaining = capture_drain_limit;
        let mut draining_expired = HashSet::new();
        while next < batches.len() || !pending.is_empty() {
            check(executor.client, deadline)?;
            let now = Instant::now();
            let expired: Vec<_> = pending
                .iter()
                .filter(|(_, entry): &(&usize, &Pending)| now >= entry.deadline)
                .map(|(index, _)| *index)
                .collect();
            let cohort_len = draining_expired.len();
            draining_expired.extend(expired.iter().copied());
            if draining_expired.len() > cohort_len {
                capture_drain_remaining = capture_drain_limit;
            }
            // A callback can consume the rest of another probe's timeout after
            // its reply has already entered a capture queue. Give each expired
            // cohort enough fair rotations to reach every record that could
            // occupy the partitioned queues, even if newer traffic refills
            // slots. Correlation below still enforces each ingress deadline.
            let draining_captures = !expired.is_empty() && capture_drain_remaining > 0;
            if !draining_captures {
                if !expired.is_empty() {
                    for index in expired {
                        complete(
                            index,
                            batches,
                            &mut pending,
                            &mut retained,
                            emit,
                            &mut failed_probe,
                            &mut evidence,
                        )?;
                    }
                }
                draining_expired.clear();
                capture_drain_remaining = capture_drain_limit;
            }
            while !draining_captures
                && next < batches.len()
                && pending.len() < options.max_in_flight
                && Instant::now() >= next_send
                && retained.saturating_add(plan.costs[next].memory) <= options.max_prepared_bytes
            {
                check(executor.client, deadline)?;
                let batch = &batches[next];
                failed_probe = Some(batch.probe.clone());
                let planned = prepare::planned(
                    executor.client,
                    batch,
                    plan.routes[&batch.probe.address].clone(),
                    &builder,
                    &executor.options.send,
                    deadline,
                )?;
                if planned.preliminary_build.bytes.len() != plan.costs[next].wire {
                    return Err(limit("changed preparation size", plan.costs[next].wire));
                }
                let mut send = executor.options.send.clone();
                send.destination = Some(batch.probe.address);
                let prepared = executor
                    .client
                    .materialize_and_authorize(planned, &builder, &send, Some(deadline))
                    .map_err(BoundaryError::from_error)?;
                if !super::probe::sent_probe_matches(&batch.probe, &prepared.built.packet) {
                    return Err(BoundaryError::internal_execution(
                        "materialized scan packet differs from its probe",
                        "internal.scan_probe_mismatch",
                        "preserve the planned endpoint and identity",
                    ));
                }
                check(executor.client, deadline)?;
                let frame = transmit::Frame::try_new(&prepared.built.bytes, &prepared.route)
                    .map_err(BoundaryError::from_error)?;
                stats.packets_attempted += 1;
                let receipt = executor
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
                    .min(deadline);
                pending.insert(
                    next,
                    Pending {
                        sent: sent.clone(),
                        deadline: end,
                        best: None,
                        last_response: None,
                        rank: 0,
                        charge: plan.costs[next].memory,
                    },
                );
                retained += plan.costs[next].memory;
                emit(PipelineEvent::Sent { index: next, sent })?;
                failed_probe = None;
                next += 1;
                next_send = Instant::now()
                    .checked_add(spacing)
                    .ok_or_else(|| limit("pacing delay", 3600))?;
                if !spacing.is_zero() {
                    break;
                }
            }
            if next == batches.len() && pending.is_empty() {
                break;
            }
            let earliest = pending
                .values()
                .map(|entry| entry.deadline)
                .min()
                .unwrap_or(deadline)
                .min(deadline);
            let wake = if next < batches.len()
                && pending.len() < options.max_in_flight
                && retained.saturating_add(plan.costs[next].memory) <= options.max_prepared_bytes
            {
                earliest.min(next_send)
            } else {
                earliest
            };
            let mut wait = wake
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5));
            if draining_captures {
                capture_drain_remaining -= 1;
                wait = Duration::ZERO;
            }
            let Some(record) = group.next_record(wait).map_err(BoundaryError::from_error)? else {
                if draining_captures {
                    capture_drain_remaining = 0;
                }
                continue;
            };
            if !seen.insert(record.captured.identity()) {
                continue;
            }
            seen_order.push_back(record.captured.identity());
            if seen_order.len() > options.max_evidence_frames
                && let Some(old) = seen_order.pop_front()
            {
                seen.remove(&old);
            }
            let captured = record.captured;
            let raw = captured.frame.clone();
            let decoded = match decoder.decode(captured.frame, executor.options.decode.clone()) {
                Ok(decoded) => decoded,
                Err(error) => {
                    if diagnostics.insert("decode") {
                        emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                            "scan.decode_error",
                            error.to_string(),
                        )))?;
                    }
                    if undecoded < options.max_undecoded {
                        emit(PipelineEvent::Undecoded { frame: raw })?;
                        undecoded += 1;
                    }
                    continue;
                }
            };
            if decoded
                .diagnostics
                .iter()
                .any(Diagnostic::is_checksum_failure)
            {
                if diagnostics.insert("integrity") {
                    emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.integrity_rejected",
                        "checksum-invalid capture was not correlated",
                    )))?;
                }
                continue;
            }
            let Some(received) = captured.received_at else {
                if diagnostics.insert("ingress") {
                    emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "capture.ingress_time_unavailable",
                        "capture lacks a monotonic ingress marker and was not correlated",
                    )))?;
                }
                continue;
            };
            let candidates = ranked_candidates(
                &pending,
                batches,
                &executor.client.registry,
                &decoded,
                &plan.interfaces[record.source],
                received,
            );
            if candidates.len() != 1 {
                if candidates.len() > 1 && diagnostics.insert("ambiguous") {
                    emit(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.ambiguous_response",
                        "capture matched multiple pending probes and was not attributed",
                    )))?;
                }
                continue;
            }
            let (index, rank, definitive) = candidates[0];
            let entry = pending.get_mut(&index).expect("candidate is pending");
            if entry.best.is_none() || rank > entry.rank {
                if let Some(previous) = &entry.best {
                    evidence.frames -= 1;
                    evidence.bytes -= previous.response.frame.bytes().len();
                }
                retain(raw.bytes().len(), &mut evidence, options)?;
                entry.rank = rank;
                entry.best = Some(crate::exchange::Response {
                    request_index: 0,
                    response: decoded,
                    latency: received
                        .duration_since(entry.sent.timing().freshness_marker().monotonic()),
                });
            }
            if definitive {
                complete(
                    index,
                    batches,
                    &mut pending,
                    &mut retained,
                    emit,
                    &mut failed_probe,
                    &mut evidence,
                )?;
            }
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
            pending: pending_evidence(&pending, batches),
            failed_probe,
            capture_sources,
            cleanup,
        })),
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
    pending: &mut BTreeMap<usize, Pending>,
    retained: &mut usize,
    emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
    failed: &mut Option<super::Probe>,
    usage: &mut EvidenceUsage,
) -> Result<(), BoundaryError> {
    let entry = pending.get_mut(&index).expect("completed pending probe");
    entry.last_response = entry
        .best
        .as_ref()
        .map(|response| response.response.frame.clone());
    *failed = Some(batches[index].probe.clone());
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
    let entry = pending.remove(&index).expect("completed pending probe");
    *retained -= entry.charge;
    if let Some(response) = entry.last_response {
        usage.frames -= 1;
        usage.bytes -= response.bytes().len();
    }
    *failed = None;
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
