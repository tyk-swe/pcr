// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod correlation;
mod prepare;
use super::{PipelineEvent, PipelineOptions};
use crate::probe::Batch;
use crate::scan::{Attribution, PendingEvidence, PipelineFailure, Probe, SentProbe};
use crate::{
    Client, Stats,
    clock::Clock,
    evidence::{ExecutionPermit, RetentionBudget, RetentionError, SentPacket},
    execution::{ExchangeExecutor, evidence::candidate_precedes, limits::check_rate, rate_delay},
    preparation::RebuildError,
    probe::Evidence,
    providers::{CaptureProviders, PacketProviders},
    scan::error::Probes,
};
use correlation::{Best, SeenFrames, candidates, definitive, settled};
use packetcraftr_core::{
    budget::Deadline,
    decode::Dissector,
    diagnostic::Diagnostic,
    error::{BoundaryError, Classification as ErrorClassification, Kind},
    frame::Frame,
};
use packetcraftr_netio::{
    Error as LiveIoError,
    capture::{self, Group, GroupRequest, Session as _},
    deadline::MAX_WAIT,
};
use prepare::{AdmittedProbe, Plan};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    iter::Peekable,
    sync::Arc,
    time::{Duration, Instant},
};

struct Pending {
    sent: Arc<SentPacket>,
    deadline: Instant,
    best: Option<Best>,
    last_response: Option<Frame>,
    charge: usize,
}
#[derive(Clone, Copy)]
struct Planned<'b> {
    probe: &'b Probe,
    permit: ExecutionPermit,
}

impl<'b> Planned<'b> {
    fn new(batch: &'b Batch<Probe>) -> Result<Self, BoundaryError> {
        Ok(Self {
            probe: batch.probe()?,
            permit: batch.permit,
        })
    }
}

fn validate_options(
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
) -> Result<(), BoundaryError> {
    let within = |value: usize, maximum: usize| (1..=maximum).contains(&value);
    let bounds = [
        (
            "probes",
            crate::scan::MAX_PROBES,
            within(batches.len(), crate::scan::MAX_PROBES),
        ),
        (
            "max_in_flight",
            crate::scan::MAX_IN_FLIGHT,
            within(options.max_in_flight, crate::scan::MAX_IN_FLIGHT),
        ),
        (
            "max_prepared_bytes",
            crate::scan::MAX_PREPARED_BYTES,
            within(options.max_prepared_bytes, crate::scan::MAX_PREPARED_BYTES),
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
            crate::scan::MAX_RATE as usize,
            check_rate(&Probes, "probes_per_second", options.probes_per_second).is_ok(),
        ),
        (
            "max_duration",
            max_wait_secs(),
            !options.max_duration.is_zero() && options.max_duration <= MAX_WAIT,
        ),
    ];
    match bounds.into_iter().find(|(_, _, holds)| !holds) {
        Some((field, maximum, _)) => Err(limit(field, maximum)),
        None => Ok(()),
    }
}

fn max_wait_secs() -> usize {
    usize::try_from(MAX_WAIT.as_secs()).unwrap_or(usize::MAX)
}

pub(in crate::scan) fn limit(field: &'static str, maximum: usize) -> BoundaryError {
    BoundaryError::new(
        format!("scan pipeline exceeds {field}={maximum}"),
        ErrorClassification::new("policy.scan_pipeline_limit", Kind::Policy, None),
        Vec::new(),
    )
}
fn until<P: PacketProviders, K: Clock>(client: &Client<P, K>, end: Instant) -> Deadline {
    Deadline::new(end.saturating_duration_since(client.now()))
        .with_cancellation(client.cancellation.clone())
}
fn check<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    deadline: Instant,
) -> Result<(), BoundaryError> {
    client
        .check_cancelled()
        .map_err(BoundaryError::from_error)?;
    if client.now() >= deadline {
        return Err(BoundaryError::new(
            "packet scan pipeline reached the operation deadline",
            ErrorClassification::new("policy.scan_duration_limit", Kind::Policy, None),
            Vec::new(),
        ));
    }
    Ok(())
}
pub(super) fn run<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: PipelineOptions,
    emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
) -> Result<Stats, BoundaryError> {
    validate_options(batches, &options)?;
    let started = executor.client.now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let preparation = until(executor.client, deadline);
    let mut pipeline = Pipeline::open(
        executor,
        batches,
        options,
        deadline,
        started,
        &preparation,
        emit,
    )?;
    let result = pipeline.drive();
    pipeline.finish(result)
}

type CaptureSession<P> = <<P as CaptureProviders>::Capture as capture::Provider>::Capture;

struct Pipeline<'a, P: PacketProviders, K> {
    executor: &'a ExchangeExecutor<'a, P, K>,
    batches: &'a [Batch<Probe>],
    planned: Vec<Planned<'a>>,
    options: PipelineOptions,
    deadline: Instant,
    started: Instant,
    emit: &'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    plan: Plan<'a, P, K>,
    group: Group<CaptureSession<P>>,
    decoder: Dissector,
    spacing: Duration,
    stats: Stats,
    pending: BTreeMap<usize, Pending>,
    /// Up to `max_in_flight` settled probes and their memory charges, so
    /// replies after settlement can be retained as late. Admission evicts
    /// the oldest cached probes when the preparation budget needs space.
    recent: VecDeque<(usize, Arc<SentPacket>, usize)>,
    retained: usize,
    evidence: RetentionBudget,
    failed_probe: Option<Probe>,
    seen: SeenFrames,
    diagnostics: HashSet<&'static str>,
    next: usize,
    next_send: Instant,
    admitted: Peekable<std::vec::IntoIter<AdmittedProbe>>,
    capture_drain_limit: usize,
    capture_drain_remaining: usize,
    draining_expired: HashSet<usize>,
}

impl<'a, P: PacketProviders, K: Clock> Pipeline<'a, P, K> {
    fn open(
        executor: &'a ExchangeExecutor<'a, P, K>,
        batches: &'a [Batch<Probe>],
        options: PipelineOptions,
        deadline: Instant,
        started: Instant,
        preparation: &'a Deadline,
        emit: &'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Self, BoundaryError> {
        let planned = batches
            .iter()
            .map(Planned::new)
            .collect::<Result<Vec<_>, _>>()?;
        let mut plan = prepare::plan(executor, &planned, options, deadline, preparation)?;
        let request = GroupRequest {
            interfaces: plan.interfaces.clone(),
            limits: executor.collection.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let mut group = Group::new(&request).map_err(BoundaryError::from_error)?;
        group
            .arm(
                executor.client.providers.capture(),
                &until(executor.client, deadline),
            )
            .map_err(BoundaryError::from_error)?;
        let source_count = group.sources().len();
        let capture_drain_limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * source_count;
        Ok(Self {
            executor,
            batches,
            planned,
            options,
            deadline,
            started,
            emit,
            group,
            decoder: Dissector::new(executor.client.registry.clone()),
            spacing: Duration::ZERO,
            stats: Stats::default(),
            pending: BTreeMap::new(),
            recent: VecDeque::new(),
            retained: plan.base_bytes,
            evidence: RetentionBudget::default(),
            failed_probe: None,
            seen: SeenFrames::new(options.max_evidence_frames),
            diagnostics: HashSet::new(),
            next: 0,
            next_send: started,
            admitted: std::mem::take(&mut plan.probes).into_iter().peekable(),
            plan,
            capture_drain_limit,
            capture_drain_remaining: capture_drain_limit,
            draining_expired: HashSet::new(),
        })
    }

    /// Runs the scan to completion or first failure. The caller passes the
    /// result to [`Self::finish`] either way.
    fn drive(&mut self) -> Result<(), BoundaryError> {
        check(self.executor.client, self.deadline)?;
        self.group
            .wait_ready(&until(self.executor.client, self.deadline))
            .map_err(BoundaryError::from_error)?;
        self.spacing = rate_delay(
            &Probes,
            "probes_per_second",
            1,
            self.options.probes_per_second,
        )
        .map_err(BoundaryError::from_error)?;
        self.next_send = self.executor.client.now();
        while self.next < self.batches.len() || !self.pending.is_empty() {
            check(self.executor.client, self.deadline)?;
            let draining_captures = self.settle_expired()?;
            self.send_ready(draining_captures)?;
            if self.next == self.batches.len() && self.pending.is_empty() {
                break;
            }
            let Some(captured) = self.read_frame(draining_captures)? else {
                continue;
            };
            self.ingest(captured)?;
        }
        Ok(())
    }

    /// Completes the probes past their timeout once the capture queues have
    /// been drained, and reports whether they are still being drained.
    fn settle_expired(&mut self) -> Result<bool, BoundaryError> {
        let now = self.executor.client.now();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, entry): &(&usize, &Pending)| now >= entry.deadline)
            .map(|(index, _)| *index)
            .collect();
        let cohort_len = self.draining_expired.len();
        self.draining_expired.extend(expired.iter().copied());
        if self.draining_expired.len() > cohort_len {
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        // A callback can consume the rest of another probe's timeout after
        // its reply has already entered a capture queue.
        let draining_captures = !expired.is_empty() && self.capture_drain_remaining > 0;
        if !draining_captures {
            for index in expired {
                self.complete(index)?;
            }
            self.draining_expired.clear();
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        Ok(draining_captures)
    }

    fn send_ready(&mut self, draining_captures: bool) -> Result<(), BoundaryError> {
        while !draining_captures
            && self.pending.len() < self.options.max_in_flight
            && self.executor.client.now() >= self.next_send
        {
            while self.admitted.peek().is_some_and(|probe| {
                self.retained.saturating_add(probe.memory) > self.options.max_prepared_bytes
            }) && let Some((_, _, charge)) = self.recent.pop_front()
            {
                self.retained -= charge;
            }
            let Some(probe) = self.admitted.next_if(|probe| {
                self.retained.saturating_add(probe.memory) <= self.options.max_prepared_bytes
            }) else {
                break;
            };
            self.send(probe)?;
            if !self.spacing.is_zero() {
                break;
            }
        }
        Ok(())
    }

    fn send(&mut self, AdmittedProbe { cost, memory }: AdmittedProbe) -> Result<(), BoundaryError> {
        let client = self.executor.client;
        check(client, self.deadline)?;
        let batch = &self.batches[self.next];
        let probe = self.planned[self.next].probe;
        self.failed_probe = Some(probe.clone());
        let prepared = self
            .plan
            .discovery
            .rebuild(
                probe.packet(),
                &self.plan.routes[&(
                    probe.address,
                    probe.scope.as_ref().map(|scope| scope.interface.clone()),
                )],
                cost,
            )
            .map_err(|error| match error {
                RebuildError::Changed { admitted } => limit("changed preparation size", admitted),
                RebuildError::Preparation(source) => BoundaryError::from_error(source),
            })?;
        if !crate::scan::plan::packet::sent_probe_matches(probe, &prepared.built().packet) {
            return Err(BoundaryError::internal_execution(
                "materialized scan packet differs from its probe",
                "internal.scan_probe_mismatch",
                "preserve the planned endpoint and identity",
            ));
        }
        check(client, self.deadline)?;
        self.stats.packets_attempted += 1;
        let sent = Arc::new(
            prepared
                .transmit(client.providers.transmit(), || Ok::<(), LiveIoError>(()))
                .map_err(BoundaryError::from_error)?,
        );
        self.stats.packets_completed += 1;
        self.stats.bytes = self
            .stats
            .bytes
            .checked_add(sent.bytes_sent() as u64)
            .ok_or_else(|| limit("sent bytes", usize::MAX))?;
        let end = sent
            .timing()
            .freshness_marker()
            .monotonic()
            .checked_add(batch.timeout)
            .ok_or_else(|| limit("probe timeout", max_wait_secs()))?
            .min(self.deadline);
        self.pending.insert(
            self.next,
            Pending {
                sent: sent.clone(),
                deadline: end,
                best: None,
                last_response: None,
                charge: memory,
            },
        );
        self.retained += memory;
        (self.emit)(PipelineEvent::Sent {
            index: self.next,
            sent,
        })?;
        self.failed_probe = None;
        self.next += 1;
        self.next_send = client
            .now()
            .checked_add(self.spacing)
            .ok_or_else(|| limit("pacing delay", max_wait_secs()))?;
        Ok(())
    }

    fn wake_time(&mut self) -> Instant {
        let earliest = self
            .pending
            .values()
            .map(|entry| entry.deadline)
            .min()
            .unwrap_or(self.deadline)
            .min(self.deadline);
        if self.pending.len() < self.options.max_in_flight
            && self.admitted.peek().is_some_and(|probe| {
                self.retained.saturating_add(probe.memory) <= self.options.max_prepared_bytes
            })
        {
            earliest.min(self.next_send)
        } else {
            earliest
        }
    }

    fn read_frame(
        &mut self,
        draining_captures: bool,
    ) -> Result<Option<capture::Captured>, BoundaryError> {
        let wake = self.wake_time();
        let mut wait = wake
            .saturating_duration_since(self.executor.client.now())
            .min(Duration::from_millis(5));
        if draining_captures {
            self.capture_drain_remaining -= 1;
            wait = Duration::ZERO;
        }
        let wait = Deadline::new(wait).with_cancellation(self.executor.client.cancellation.clone());
        let captured = self
            .group
            .next_captured_frame(&wait)
            .map_err(BoundaryError::from_error)?;
        if captured.is_none() && draining_captures {
            self.capture_drain_remaining = 0;
        }
        Ok(captured)
    }

    fn ingest(&mut self, captured: capture::Captured) -> Result<(), BoundaryError> {
        if !self.seen.insert(captured.identity()) {
            return Ok(());
        }
        let source = captured.source;
        let raw = captured.frame.clone();
        let decoded = match self
            .decoder
            .decode(captured.frame, self.executor.collection.decode.clone())
        {
            Ok(decoded) => decoded,
            Err(error) => {
                if self.diagnostics.insert("decode") {
                    (self.emit)(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.decode_error",
                        packetcraftr_core::error::render(&error),
                    )))?;
                }
                (self.emit)(PipelineEvent::Undecoded { frame: raw })?;
                return Ok(());
            }
        };
        if decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            if self.diagnostics.insert("integrity") {
                (self.emit)(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.integrity_rejected",
                    "checksum-invalid capture was not correlated",
                )))?;
            }
            return Ok(());
        }
        let Some(received) = captured.received_at else {
            if self.diagnostics.insert("ingress") {
                (self.emit)(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "capture.ingress_time_unavailable",
                    "capture lacks a monotonic ingress marker and was not correlated",
                )))?;
            }
            return Ok(());
        };
        let mut candidates = candidates(
            &self.pending,
            &self.planned,
            &self.executor.client.registry,
            &decoded,
            &self.plan.interfaces[source],
            received,
        );
        if candidates.is_empty() {
            // Pending probes whose window closed have not settled yet, but
            // a frame after their deadline cannot be their outcome either.
            let expired = self
                .pending
                .iter()
                .filter(|(_, entry)| received > entry.deadline)
                .map(|(index, entry)| (*index, &entry.sent));
            let recent = self.recent.iter().map(|(index, sent, _)| (*index, sent));
            let settled = settled(
                expired.chain(recent),
                &self.planned,
                &self.executor.client.registry,
                &decoded,
                &self.plan.interfaces[source],
                received,
            );
            return match settled.as_slice() {
                [] => Ok(()),
                [index] => self.unattributed(raw, Attribution::Late, Some(*index)),
                _ => self.unattributed(raw, Attribution::Ambiguous, None),
            };
        }
        if candidates.len() > 1 {
            if self.diagnostics.insert("ambiguous") {
                (self.emit)(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.ambiguous_response",
                    "capture matched multiple pending probes and was not attributed",
                )))?;
            }
            return self.unattributed(raw, Attribution::Ambiguous, None);
        }
        let (index, observation) = candidates.pop().expect("one candidate");
        let definitive = definitive(&observation);
        let entry = self.pending.get_mut(&index).expect("candidate is pending");
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
            self.evidence
                .replace(
                    entry
                        .best
                        .as_ref()
                        .map(|previous| previous.response.response.frame.bytes().len()),
                    raw.bytes().len(),
                    self.options.max_evidence_frames,
                    self.options.max_evidence_bytes,
                )
                .map_err(|error| match error {
                    RetentionError::FrameCountOverflow | RetentionError::FrameLimit => {
                        limit("evidence frames", self.options.max_evidence_frames)
                    }
                    RetentionError::ByteCountOverflow | RetentionError::ByteLimit => {
                        limit("evidence bytes", self.options.max_evidence_bytes)
                    }
                })?;
            let superseded = entry.best.replace(candidate);
            if let Some(previous) = superseded {
                self.unattributed(
                    previous.response.response.frame,
                    Attribution::Duplicate,
                    Some(index),
                )?;
            }
        } else {
            self.unattributed(raw, Attribution::Duplicate, Some(index))?;
        }
        if definitive {
            self.complete(index)?;
        }
        Ok(())
    }

    fn unattributed(
        &mut self,
        frame: Frame,
        attribution: Attribution,
        index: Option<usize>,
    ) -> Result<(), BoundaryError> {
        let sequence = index.map(|index| self.planned[index].probe.sequence);
        (self.emit)(PipelineEvent::Unattributed {
            frame,
            attribution,
            sequence,
        })
    }

    fn complete(&mut self, index: usize) -> Result<(), BoundaryError> {
        let entry = self
            .pending
            .get_mut(&index)
            .expect("completed pending probe");
        entry.last_response = entry
            .best
            .as_ref()
            .map(|best| best.response.response.frame.clone());
        self.failed_probe = Some(self.planned[index].probe.clone());
        let stats = Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: entry.sent.bytes_sent() as u64,
            elapsed: entry.sent.timing().freshness_marker().monotonic().elapsed(),
            capture: Default::default(),
        };
        let execution = Evidence {
            permit: self.planned[index].permit,
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
        (self.emit)(PipelineEvent::Completed { index, execution })?;
        let entry = self
            .pending
            .remove(&index)
            .expect("completed pending probe");
        if let Some(response) = entry.last_response {
            self.evidence.release(response.bytes().len());
        }
        if self.recent.len() == self.options.max_in_flight
            && let Some((_, _, charge)) = self.recent.pop_front()
        {
            self.retained -= charge;
        }
        self.recent.push_back((index, entry.sent, entry.charge));
        self.failed_probe = None;
        Ok(())
    }

    fn finish(mut self, result: Result<(), BoundaryError>) -> Result<Stats, BoundaryError> {
        let mut cleanup = None;
        let mut result = result;
        // A group failure already shut every source down; this reports that
        // cleanup, or performs it after any other exit.
        if let Err(error) = self.group.shutdown() {
            if result.is_ok() {
                result = Err(BoundaryError::from_error(error));
            } else {
                cleanup = Some(Box::new(error));
            }
        }
        let capture_sources = self.group.snapshot();
        for source in &capture_sources {
            if let Some(sum) = self.stats.capture.checked_add(source.statistics) {
                self.stats.capture = sum;
            } else {
                if result.is_ok() {
                    result = Err(limit("capture statistics", usize::MAX));
                }
                break;
            }
        }
        self.stats.elapsed = self
            .executor
            .client
            .now()
            .saturating_duration_since(self.started);
        let result = result.and_then(|()| {
            for source in &capture_sources {
                if let Some(loss) = source.statistics.evidence_loss_error() {
                    if source.limits.overflow_policy == capture::OverflowPolicy::Fail {
                        return Err(BoundaryError::from_error(loss));
                    }
                    (self.emit)(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "capture.evidence_incomplete",
                        format!("source {}: {loss}", source.index),
                    )))?;
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => Ok(self.stats),
            Err(source) => Err(BoundaryError::from_error(PipelineFailure {
                source,
                stats: self.stats,
                pending: pending_evidence(&self.pending, &self.planned),
                failed_probe: self.failed_probe,
                capture_sources,
                cleanup,
            })),
        }
    }
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
