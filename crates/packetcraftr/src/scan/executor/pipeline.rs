// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod admission;
mod capture_lifecycle;
mod correlation;
mod settlement;
mod streaming;
mod transmission;

pub(super) use admission::{admit, admit_adaptive};
pub(super) use streaming::run_stream;

mod expiry;
mod prepare;
use super::{PipelineEvent, PipelineFeed, PipelineOptions};
use crate::probe::Batch;
use crate::scan::{PendingEvidence, PipelineFailure, Probe, SentProbe};
use crate::{
    Client, Stats,
    clock::Clock,
    evidence::{RetentionBudget, SentPacket},
    execution::{ExchangeExecutor, limits::check_rate, rate_delay},
    providers::{CaptureProviders, PacketProviders},
    scan::error::probe_error,
};
use correlation::{Best, CandidateIndex, SeenFrames};
use packetcraftr_core::{
    budget::Deadline,
    decode::Dissector,
    error::{BoundaryError, Classification as ErrorClassification, Kind},
    frame::Frame,
};
use packetcraftr_netio::{
    capture::{self, Group, GroupRequest, Session as _},
    deadline::MAX_WAIT,
    interface,
};
use prepare::{AdmittedProbe, Plan};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

struct Pending {
    sent: Arc<SentPacket>,
    deadline: Instant,
    best: Option<Best>,
    passed: Vec<crate::exchange::Response>,
    last_response: Option<Frame>,
    charge: usize,
}
#[derive(Clone, Copy)]
struct Planned<'b> {
    probe: &'b Probe,
}

impl<'b> Planned<'b> {
    fn new(batch: &'b Batch<Probe>) -> Result<Self, BoundaryError> {
        Ok(Self {
            probe: batch.probe()?,
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
            check_rate(probe_error, "probes_per_second", options.probes_per_second).is_ok(),
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
fn until<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    end: Instant,
    control: &Deadline,
) -> Deadline {
    Deadline::new(end.saturating_duration_since(client.now()))
        .with_cancellation(client.cancellation.clone())
        .with_parent(Some(Arc::new(control.clone())))
}
fn check<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    deadline: Instant,
    control: &Deadline,
) -> Result<(), BoundaryError> {
    control.enforce().map_err(BoundaryError::from_error)?;
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
    history: &mut super::reply_history::ReplyHistory,
) -> Result<Stats, BoundaryError> {
    validate_options(batches, &options)?;
    let started = executor.client.now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let preparation = until(executor.client, deadline, &options.control);
    let mut pipeline = Pipeline::open(
        executor,
        batches,
        options,
        deadline,
        started,
        &preparation,
        (emit, history),
    )?;
    let result = pipeline.drive();
    pipeline.finish(result)
}

pub(in crate::scan) struct AdaptiveAdmission {
    interfaces: Vec<interface::Id>,
    window: usize,
    many_interfaces: bool,
    max_description_bytes: usize,
    max_route_bytes: usize,
    max_map_route_bytes: usize,
    source_metadata_bytes: usize,
    max_source_name_bytes: usize,
    max_probe_bytes: usize,
    summary_bytes: usize,
}

type CaptureSession<P> = <<P as CaptureProviders>::Capture as capture::Provider>::Capture;

enum BatchStorage<'a> {
    Borrowed(&'a Batch<Probe>),
    Owned(Batch<Probe>),
}
impl BatchStorage<'_> {
    fn batch(&self) -> &Batch<Probe> {
        match self {
            Self::Borrowed(batch) => batch,
            Self::Owned(batch) => batch,
        }
    }
}
struct Descriptor<'a> {
    batch: BatchStorage<'a>,
    host_deadline: Option<Instant>,
    route: Option<Box<crate::preparation::AuthorizedRoute>>,
}
impl Descriptor<'_> {
    fn probe(&self) -> &Probe {
        &self.batch.batch().probes[0]
    }
}
enum Output<'a> {
    Fixed(&'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>),
    Stream(&'a mut dyn PipelineFeed),
}
impl Output<'_> {
    fn event(&mut self, event: PipelineEvent) -> Result<(), BoundaryError> {
        match self {
            Self::Fixed(emit) => emit(event),
            Self::Stream(feed) => feed.event(event),
        }
    }
}
struct Streaming {
    done: bool,
    next_ready: Option<Instant>,
    max_probe_bytes: usize,
    max_descriptor_bytes: usize,
    max_source_name_bytes: usize,
}

struct InitialState<'a, P, K> {
    plan: Plan<'a, P, K>,
    descriptions: BTreeMap<usize, Descriptor<'a>>,
    streaming: Option<Streaming>,
}

struct Pipeline<'a, P: PacketProviders, K> {
    history: &'a mut super::reply_history::ReplyHistory,
    executor: &'a ExchangeExecutor<'a, P, K>,
    descriptions: BTreeMap<usize, Descriptor<'a>>,
    ready: BTreeMap<usize, AdmittedProbe>,
    armed_ready: BTreeSet<usize>,
    ready_deadlines: BTreeSet<(Instant, usize)>,
    streaming: Option<Streaming>,
    options: PipelineOptions,
    deadline: Instant,
    started: Instant,
    output: Output<'a>,
    plan: Plan<'a, P, K>,
    group: Group<CaptureSession<P>>,
    group_accounted: bool,
    aggregate_quality: capture::ObservationQuality,
    qualification: Option<(crate::scan::Stage, u64, u64)>,
    decoder: Dissector,
    spacing: Duration,
    stats: Stats,
    pending: BTreeMap<usize, Pending>,
    recent: VecDeque<(usize, Arc<SentPacket>, usize)>,
    recent_sent: BTreeMap<usize, Arc<SentPacket>>,
    candidates: CandidateIndex,
    retained: usize,
    evidence: RetentionBudget,
    failed_probe: Option<Probe>,
    seen: SeenFrames,
    ingress_unknown: bool,
    diagnostics: HashSet<&'static str>,
    next_send: Instant,
    capture_drain_limit: usize,
    capture_drain_remaining: usize,
    deadlines: expiry::PendingDeadlines,
}

impl<'a, P: PacketProviders, K: Clock> Pipeline<'a, P, K> {
    fn open(
        executor: &'a ExchangeExecutor<'a, P, K>,
        batches: &'a [Batch<Probe>],
        options: PipelineOptions,
        deadline: Instant,
        started: Instant,
        preparation: &'a Deadline,
        (emit, history): (
            &'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
            &'a mut super::reply_history::ReplyHistory,
        ),
    ) -> Result<Self, BoundaryError> {
        let planned = batches
            .iter()
            .map(Planned::new)
            .collect::<Result<Vec<_>, _>>()?;
        let plan = prepare::plan(executor, &planned, &options, deadline, preparation, true)?;
        let descriptions = batches
            .iter()
            .enumerate()
            .map(|(index, batch)| {
                (
                    index,
                    Descriptor {
                        batch: BatchStorage::Borrowed(batch),
                        host_deadline: None,
                        route: None,
                    },
                )
            })
            .collect();
        Self::assemble(
            executor,
            options,
            deadline,
            started,
            Output::Fixed(emit),
            history,
            InitialState {
                plan,
                descriptions,
                streaming: None,
            },
        )
    }

    fn assemble(
        executor: &'a ExchangeExecutor<'a, P, K>,
        options: PipelineOptions,
        deadline: Instant,
        started: Instant,
        output: Output<'a>,
        history: &'a mut super::reply_history::ReplyHistory,
        initial: InitialState<'a, P, K>,
    ) -> Result<Self, BoundaryError> {
        let InitialState {
            mut plan,
            descriptions,
            streaming,
        } = initial;
        let request = GroupRequest {
            interfaces: plan.interfaces.clone(),
            limits: executor.collection.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let mut group = Group::new(&request).map_err(BoundaryError::from_error)?;
        let armed = group.arm(
            executor.client.providers.capture(),
            &until(executor.client, deadline, &options.control),
        );
        check(executor.client, deadline, &options.control)?;
        armed.map_err(BoundaryError::from_error)?;
        let source_count = group.sources().len();
        let capture_drain_limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * source_count;
        let capacity = if streaming.is_some() {
            options.max_in_flight.saturating_mul(2)
        } else {
            descriptions
                .len()
                .min(options.max_in_flight.saturating_mul(2))
        };
        let ready = descriptions
            .keys()
            .copied()
            .zip(std::mem::take(&mut plan.probes))
            .collect::<BTreeMap<_, _>>();
        let armed_ready = ready.keys().copied().collect();
        let ready_deadlines = descriptions
            .iter()
            .filter_map(|(index, description)| {
                description.host_deadline.map(|deadline| (deadline, *index))
            })
            .collect();
        let seen = SeenFrames::new(options.max_evidence_frames);
        let retained = plan.base_bytes;
        Ok(Self {
            history,
            executor,
            descriptions,
            ready,
            armed_ready,
            ready_deadlines,
            streaming,
            options,
            deadline,
            started,
            output,
            plan,
            group,
            group_accounted: false,
            aggregate_quality: capture::ObservationQuality::NoReportedLoss,
            qualification: None,
            decoder: Dissector::new(executor.operation.registry.clone()),
            spacing: Duration::ZERO,
            stats: Stats::default(),
            pending: BTreeMap::new(),
            recent: VecDeque::new(),
            recent_sent: BTreeMap::new(),
            candidates: CandidateIndex::new(source_count, capacity),
            retained,
            evidence: RetentionBudget::default(),
            failed_probe: None,
            seen,
            ingress_unknown: false,
            diagnostics: HashSet::new(),
            next_send: started,
            capture_drain_limit,
            capture_drain_remaining: capture_drain_limit,
            deadlines: expiry::PendingDeadlines::default(),
        })
    }

    /// Runs the scan to completion or first failure. The caller passes the
    /// result to [`Self::finish`] either way.
    fn drive(&mut self) -> Result<(), BoundaryError> {
        check(self.executor.client, self.deadline, &self.options.control)?;
        let ready = self.group.wait_ready(&until(
            self.executor.client,
            self.deadline,
            &self.options.control,
        ));
        check(self.executor.client, self.deadline, &self.options.control)?;
        ready.map_err(BoundaryError::from_error)?;
        self.spacing = rate_delay(
            probe_error,
            "probes_per_second",
            1,
            self.options.probes_per_second,
        )
        .map_err(BoundaryError::from_error)?;
        self.next_send = self.executor.client.now();
        while !self.done() || !self.ready.is_empty() || !self.pending.is_empty() {
            check(self.executor.client, self.deadline, &self.options.control)?;
            let draining_captures = self.settle_expired()?;
            self.refill(draining_captures)?;
            self.send_ready(draining_captures)?;
            if self.done() && self.ready.is_empty() && self.pending.is_empty() {
                break;
            }
            let Some(captured) = self.read_frame(draining_captures)? else {
                continue;
            };
            self.ingest(captured)?;
        }
        check(self.executor.client, self.deadline, &self.options.control)
    }

    fn finish(mut self, result: Result<(), BoundaryError>) -> Result<Stats, BoundaryError> {
        let mut cleanup = None;
        let mut result = result;
        if !self.group_accounted {
            if let Err(error) = self.group.shutdown() {
                if result.is_ok() {
                    result = Err(BoundaryError::from_error(error));
                } else {
                    cleanup = Some(Box::new(error));
                }
            }
            if let Err(error) = self.account_group(result.is_ok())
                && result.is_ok()
            {
                result = Err(error);
            }
        }
        let capture_sources = self.group.snapshot();
        self.stats.elapsed = self
            .executor
            .client
            .now()
            .saturating_duration_since(self.started);
        let result = result.and_then(|()| {
            self.options
                .control
                .enforce()
                .map_err(BoundaryError::from_error)?;
            let quality = self.aggregate_quality;
            let quality = if self.ingress_unknown {
                quality.combine(capture::ObservationQuality::Unknown)
            } else {
                quality
            };
            // The interval is sparse when hosts expired before send. It
            // qualifies only published attempts, never omissions or replies.
            if let Some((stage, first, last)) = self.qualification {
                self.output.event(PipelineEvent::Qualification(
                    crate::scan::Qualification::new(stage, first, last, quality)
                        .expect("ordered stage sequence interval"),
                ))?;
            }
            self.options
                .control
                .enforce()
                .map_err(BoundaryError::from_error)
        });
        let Err(source) = result else {
            return Ok(self.stats);
        };
        // The failure reports the operation's traffic before this pipeline
        // too, or only this pipeline's should the sum overflow.
        let mut stats = self.options.preceding;
        if stats.checked_add_assign(&self.stats).is_err() {
            stats = self.stats;
        }
        Err(BoundaryError::from_error(PipelineFailure {
            source,
            stats,
            pending: pending_evidence(&self.pending, &self.descriptions),
            failed_probe: self.failed_probe,
            capture_sources,
            cleanup,
        }))
    }
}
fn pending_evidence(
    pending: &BTreeMap<usize, Pending>,
    descriptions: &BTreeMap<usize, Descriptor<'_>>,
) -> Vec<PendingEvidence> {
    pending
        .iter()
        .map(|(index, entry)| PendingEvidence {
            sent: SentProbe {
                probe: descriptions[index].probe().clone(),
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
