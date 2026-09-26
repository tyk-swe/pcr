// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod prepare;
use super::{Batch, Classification, SentProbe, evidence::Observation, profile};
use crate::{
    Client, SentPacket, Stats,
    evidence::ExecutionPermit,
    preparation::RebuildError,
    probe::{
        ExchangeExecutor, Execution, PipelineEvent, PipelineOptions,
        evidence::{CandidateKey, candidate_precedes},
    },
};
use packetcraftr_core::{
    decode::Dissector,
    diagnostic::Diagnostic,
    error::{BoundaryError, Classification as ErrorClassification, Classified, Kind},
    frame::Frame,
};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{self, group},
    route, transmit,
};
use prepare::AdmittedProbe;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    net::IpAddr,
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
    best: Option<Best>,
    last_response: Option<Frame>,
    charge: usize,
}
/// The response a pending probe would report if it completed now, with what
/// the shared candidate ordering compares about it.
struct Best {
    response: crate::exchange::Response,
    rank: u8,
    responder: IpAddr,
}
impl Best {
    fn key(&self) -> CandidateKey<'_, IpAddr> {
        CandidateKey {
            rank: self.rank,
            tie_break: self.responder,
            latency: self.response.latency,
            bytes: self.response.response.frame.bytes().as_ref(),
        }
    }
}
/// One batch as the pipeline runs it: its only probe and the permit its
/// evidence must carry. Every batch is checked for exactly one probe before
/// anything is planned.
#[derive(Clone, Copy)]
struct Planned<'b> {
    probe: &'b super::Probe,
    permit: ExecutionPermit,
}

impl<'b> Planned<'b> {
    fn new(batch: &'b Batch) -> Result<Self, BoundaryError> {
        Ok(Self {
            probe: batch.probe()?,
            permit: batch.permit,
        })
    }
}

/// Rejects an empty or out-of-budget pipeline configuration before any
/// resource is armed, so a scan that cannot proceed arms no capture. The
/// refusal names the first bound that does not hold.
fn validate_options(batches: &[Batch], options: &PipelineOptions) -> Result<(), BoundaryError> {
    let within = |value: usize, maximum: usize| (1..=maximum).contains(&value);
    let bounds = [
        (
            "probes",
            super::MAX_PROBES,
            within(batches.len(), super::MAX_PROBES),
        ),
        ("max_in_flight", 1024, within(options.max_in_flight, 1024)),
        (
            "max_prepared_bytes",
            256 * 1024 * 1024,
            within(options.max_prepared_bytes, 256 * 1024 * 1024),
        ),
        (
            "max_evidence_frames",
            capture::MAX_CAPTURE_QUEUE_FRAMES,
            within(
                options.max_evidence_frames,
                capture::MAX_CAPTURE_QUEUE_FRAMES,
            ),
        ),
        (
            "max_evidence_bytes",
            capture::MAX_CAPTURE_QUEUE_BYTES,
            within(options.max_evidence_bytes, capture::MAX_CAPTURE_QUEUE_BYTES),
        ),
        (
            "probes_per_second",
            super::MAX_RATE as usize,
            options
                .probes_per_second
                .is_none_or(|rate| (1..=super::MAX_RATE).contains(&rate)),
        ),
        (
            "max_undecoded",
            options.max_evidence_frames,
            options.max_undecoded <= options.max_evidence_frames,
        ),
        (
            "max_duration",
            usize::try_from(super::MAX_DURATION.as_secs()).unwrap_or(usize::MAX),
            !options.max_duration.is_zero() && options.max_duration <= super::MAX_DURATION,
        ),
    ];
    match bounds.into_iter().find(|(_, _, holds)| !holds) {
        Some((field, maximum, _)) => Err(limit(field, maximum)),
        None => Ok(()),
    }
}

/// Observes every pending probe a captured record could complete: interface,
/// freshness window, transport classification, and application evidence. An
/// empty or ambiguous result leaves the frame unattributed.
fn candidates(
    pending: &BTreeMap<usize, Pending>,
    planned: &[Planned<'_>],
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<(usize, Observation)> {
    pending
        .iter()
        .filter(|(_, entry)| {
            entry.sent.route().plan.decision.interface == *native_interface
                && received >= entry.sent.timing().freshness_marker().monotonic()
                && received <= entry.deadline
        })
        .filter_map(|(index, entry)| {
            Observation::observe(
                registry,
                planned[*index].probe,
                &entry.sent.built().packet,
                decoded,
            )
            .map(|observation| (*index, observation))
        })
        .collect()
}

/// An open response with confirmed or unchecked application evidence
/// completes its probe without waiting for the rest of its timeout.
fn definitive(observation: &Observation) -> bool {
    observation.response.classification == Classification::Open
        && observation.application.as_ref().is_none_or(|evidence| {
            matches!(
                evidence.status,
                profile::Status::Confirmed | profile::Status::Unchecked
            )
        })
}

pub(super) fn limit(field: &'static str, maximum: usize) -> BoundaryError {
    BoundaryError::new(
        format!("scan pipeline exceeds {field}={maximum}"),
        ErrorClassification::new("policy.scan_pipeline_limit", Kind::Policy, None),
        Vec::new(),
    )
}
fn check<R, I>(client: &Client<R, I>, deadline: Instant) -> Result<(), BoundaryError>
where
    R: route::Provider,
    I: transmit::Provider,
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
pub(super) fn run<R, I>(
    executor: &mut ExchangeExecutor<'_, R, I>,
    batches: &[Batch],
    options: PipelineOptions,
    emit: &mut dyn FnMut(PipelineEvent<Execution>) -> Result<(), BoundaryError>,
) -> Result<Stats, BoundaryError>
where
    R: route::Provider,
    I: transmit::Provider + capture::Provider,
{
    validate_options(batches, &options)?;
    let started = Instant::now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", 3600))?;
    let planned = batches
        .iter()
        .map(Planned::new)
        .collect::<Result<Vec<_>, _>>()?;
    let mut plan = prepare::plan(executor, &planned, options, deadline)?;
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
        let decoder = Dissector::new(executor.client.registry.clone());
        let spacing = crate::clock::rate_delay(1, options.probes_per_second)
            .ok_or_else(|| limit("probe rate", super::MAX_RATE as usize))?;
        let mut next = 0usize;
        let mut next_send = Instant::now();
        let mut retained = plan.base_bytes;
        // One admitted probe per batch, consumed in send order: the next one
        // belongs to `batches[next]`.
        let mut admitted = std::mem::take(&mut plan.probes).into_iter().peekable();
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
                            &planned,
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
                && pending.len() < options.max_in_flight
                && Instant::now() >= next_send
                && let Some(AdmittedProbe { cost, memory }) = admitted.next_if(|probe| {
                    retained.saturating_add(probe.memory) <= options.max_prepared_bytes
                })
            {
                check(executor.client, deadline)?;
                let batch = &batches[next];
                let probe = planned[next].probe;
                failed_probe = Some(probe.clone());
                let prepared = plan
                    .discovery
                    .rebuild(probe.packet(), &plan.routes[&probe.address], cost)
                    .map_err(|error| match error {
                        RebuildError::Changed { admitted } => {
                            limit("changed preparation size", admitted)
                        }
                        RebuildError::Preparation(source) => BoundaryError::from_error(source),
                    })?;
                if !super::probe::sent_probe_matches(probe, &prepared.built().packet) {
                    return Err(BoundaryError::internal_execution(
                        "materialized scan packet differs from its probe",
                        "internal.scan_probe_mismatch",
                        "preserve the planned endpoint and identity",
                    ));
                }
                check(executor.client, deadline)?;
                stats.packets_attempted += 1;
                let sent = Arc::new(
                    prepared
                        .transmit(&executor.client.io, || Ok::<(), LiveIoError>(()))
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
                        charge: memory,
                    },
                );
                retained += memory;
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
            let wake = if pending.len() < options.max_in_flight
                && admitted.peek().is_some_and(|probe| {
                    retained.saturating_add(probe.memory) <= options.max_prepared_bytes
                }) {
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
                            packetcraftr_core::error::render(&error),
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
            let mut candidates = candidates(
                &pending,
                &planned,
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
            let (index, observation) = candidates.pop().expect("one candidate");
            let definitive = definitive(&observation);
            let entry = pending.get_mut(&index).expect("candidate is pending");
            let candidate = Best {
                rank: observation.rank(),
                responder: observation.response.responder,
                response: crate::exchange::Response {
                    request_index: 0,
                    response: decoded,
                    latency: received
                        .duration_since(entry.sent.timing().freshness_marker().monotonic()),
                },
            };
            if entry
                .best
                .as_ref()
                .is_none_or(|current| candidate_precedes(&candidate.key(), &current.key()))
            {
                if let Some(previous) = &entry.best {
                    evidence.frames -= 1;
                    evidence.bytes -= previous.response.response.frame.bytes().len();
                }
                retain(raw.bytes().len(), &mut evidence, options)?;
                entry.best = Some(candidate);
            }
            if definitive {
                complete(
                    index,
                    &planned,
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
            pending: pending_evidence(&pending, &planned),
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
    planned: &[Planned<'_>],
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
        .map(|best| best.response.response.frame.clone());
    *failed = Some(planned[index].probe.clone());
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: entry.sent.bytes_sent() as u64,
        elapsed: entry.sent.timing().freshness_marker().monotonic().elapsed(),
        capture: Default::default(),
    };
    let execution = Execution {
        permit: planned[index].permit,
        sent: vec![entry.sent.as_ref().clone()],
        responses: entry
            .best
            .take()
            .map(|best| best.response)
            .into_iter()
            .collect(),
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
fn pending_evidence(
    pending: &BTreeMap<usize, Pending>,
    planned: &[Planned<'_>],
) -> Vec<PendingEvidence> {
    pending
        .iter()
        .map(|(index, entry)| PendingEvidence {
            sent: SentProbe {
                probe: planned[*index].probe.clone(),
                sent: entry.sent.clone(),
            },
            response: entry
                .best
                .as_ref()
                .map(|best| best.response.response.frame.clone())
                .or_else(|| entry.last_response.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::ProbeEndpoint;
    use crate::scan::{MAX_DURATION, MAX_PROBES, MAX_RATE, Probe};

    fn options() -> PipelineOptions {
        PipelineOptions {
            max_in_flight: 2,
            probes_per_second: None,
            max_duration: Duration::from_secs(1),
            max_prepared_bytes: 1024,
            max_evidence_frames: 8,
            max_evidence_bytes: 1024,
            max_undecoded: 8,
        }
    }

    #[test]
    fn an_invalid_pipeline_option_reports_its_own_bound() {
        let batches = [Batch::single(
            Probe {
                sequence: 0,
                address: IpAddr::from([192, 0, 2, 1]),
                endpoint: ProbeEndpoint::Tcp { port: 80 },
                attempt: 1,
                udp_payload: bytes::Bytes::new(),
                udp_profile: None,
            },
            Duration::from_millis(1),
        )];
        validate_options(&batches, &options()).expect("the baseline options hold");
        let refusals = [
            (
                PipelineOptions {
                    max_in_flight: 1025,
                    ..options()
                },
                "max_in_flight=1024".to_owned(),
            ),
            (
                PipelineOptions {
                    probes_per_second: Some(0),
                    ..options()
                },
                format!("probes_per_second={}", MAX_RATE),
            ),
            (
                PipelineOptions {
                    max_undecoded: 9,
                    ..options()
                },
                "max_undecoded=8".to_owned(),
            ),
            (
                PipelineOptions {
                    max_duration: Duration::ZERO,
                    ..options()
                },
                format!("max_duration={}", MAX_DURATION.as_secs()),
            ),
        ];
        for (options, bound) in refusals {
            let error = validate_options(&batches, &options).expect_err(&bound);
            assert_eq!(error.to_string(), format!("scan pipeline exceeds {bound}"));
        }
        assert_eq!(
            validate_options(&[], &options())
                .expect_err("an empty pipeline is refused")
                .to_string(),
            format!("scan pipeline exceeds probes={}", MAX_PROBES)
        );
    }
}
