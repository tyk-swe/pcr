// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod correlation;
mod expiry;
mod prepare;
use super::{PipelineEvent, PipelineFeed, PipelineOptions};
use crate::probe::Batch;
use crate::scan::plan::replies_overlap;
use crate::scan::{Attribution, PendingEvidence, PipelineFailure, Probe, Reply, SentProbe};
use crate::{
    Client, Stats,
    clock::Clock,
    evidence::{RetentionBudget, RetentionError, SentPacket},
    execution::{ExchangeExecutor, evidence::candidate_precedes, limits::check_rate, rate_delay},
    preparation::RebuildError,
    probe::Evidence,
    providers::{CaptureProviders, PacketProviders},
    scan::error::probe_error,
};
use correlation::{
    Best, CandidateIndex, SeenFrames, definitive, indexed_candidates, indexed_settled,
};
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

/// One capture/correlation lifetime for controller-driven raw work. Initial
/// preparation is bounded by the live window; the controller supplies later
/// attempts only after settlements release capacity.
pub(super) fn run_stream<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    options: PipelineOptions,
    admission: &AdaptiveAdmission,
    attempts: usize,
    feed: &mut dyn PipelineFeed,
    history: &mut super::reply_history::ReplyHistory,
) -> Result<Stats, BoundaryError> {
    let mut options = options;
    options.max_in_flight = options.max_in_flight.min(admission.window.max(1));
    if admission.many_interfaces {
        options.max_in_flight = options.max_in_flight.min(capture::MAX_SOURCES);
    }
    let started = executor.client.now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let preparation = until(executor.client, deadline, &options.control);
    let initial = loop {
        check(executor.client, deadline, &options.control)?;
        let poll = feed.poll(options.max_in_flight, executor.client.now())?;
        if !poll.batches.is_empty() {
            break poll;
        }
        if poll.done {
            return Ok(Stats {
                elapsed: executor.client.now().saturating_duration_since(started),
                ..Stats::default()
            });
        }
        let wait = poll
            .next_ready
            .map_or(Duration::from_millis(1), |ready| {
                ready.saturating_duration_since(executor.client.now())
            })
            .min(Duration::from_millis(5));
        executor
            .client
            .clock
            .sleep(wait, &preparation)
            .map_err(|source| {
                BoundaryError::from_error(probe_error(
                    0,
                    crate::execution::Failure::Clock(Box::new(source)),
                ))
            })?;
    };
    if initial.batches.len() > options.max_in_flight
        || attempts == 0
        || attempts > crate::scan::MAX_PROBES
    {
        return Err(limit("stream attempts", crate::scan::MAX_PROBES));
    }
    for (index, offered) in initial.batches.iter().enumerate() {
        if offered.index != index {
            return Err(limit("stream attempt identity", crate::scan::MAX_PROBES));
        }
        let _ = offered.batch.probe()?;
    }
    let planned = initial
        .batches
        .iter()
        .map(|offer| Planned::new(&offer.batch))
        .collect::<Result<Vec<_>, _>>()?;
    let mut plan = prepare::plan_with_limit(
        executor,
        &planned,
        &options,
        deadline,
        &preparation,
        true,
        attempts,
    )?;
    let old_sources = plan.interfaces.len();
    let descriptions_charge = planned
        .iter()
        .map(|planned| {
            384usize.saturating_add(
                planned
                    .probe
                    .scope
                    .as_ref()
                    .map_or(0, crate::target::ResolvedZone::retained_bytes),
            )
        })
        .sum::<usize>();
    let old_indexes = correlation::index_charge(
        planned.len().min(options.max_in_flight.saturating_mul(2)),
        old_sources,
    )
    .saturating_add(expiry::charge(planned.len().min(options.max_in_flight)));
    plan.base_bytes = plan
        .base_bytes
        .checked_sub(
            descriptions_charge
                .saturating_add(old_indexes)
                .saturating_add(plan.interfaces_bytes),
        )
        .ok_or_else(|| limit("prepared accounting", options.max_prepared_bytes))?;
    let descriptor_bytes = admission
        .max_description_bytes
        .saturating_add(admission.max_route_bytes)
        .saturating_add(512);
    let source_ceiling = options.max_in_flight.min(capture::MAX_SOURCES);
    let source_bytes = source_charge(
        source_ceiling,
        admission.max_source_name_bytes,
        admission.source_metadata_bytes,
    );
    if plan
        .interfaces
        .iter()
        .any(|interface| interface.name.len() > admission.max_source_name_bytes)
        || plan
            .routes
            .values()
            .any(|route| prepare::route_charge(route) > admission.max_route_bytes)
        || plan
            .probes
            .iter()
            .any(|probe| probe.memory > admission.max_probe_bytes)
    {
        return Err(limit(
            "changed prepared descriptions",
            options.max_prepared_bytes,
        ));
    }
    plan.base_bytes = plan
        .base_bytes
        .saturating_add(
            descriptor_bytes
                .saturating_mul(options.max_in_flight)
                .saturating_mul(2),
        )
        .saturating_add(correlation::index_charge(
            options.max_in_flight.saturating_mul(2),
            source_ceiling,
        ))
        .saturating_add(expiry::charge(options.max_in_flight))
        .saturating_add(source_bytes)
        .saturating_add(admission.summary_bytes);
    // Previews are optional. Drop them before refusing the minimum runtime
    // profile, while keeping one preflight-sized preparation overlap reserved.
    for probe in plan.probes.iter_mut().rev() {
        if plan.base_bytes.saturating_add(admission.max_probe_bytes) <= options.max_prepared_bytes {
            break;
        }
        if let Some(preview) = probe.retained.take() {
            drop(preview);
            plan.base_bytes -= probe.memory;
        }
    }
    if plan.base_bytes.saturating_add(admission.max_probe_bytes) > options.max_prepared_bytes {
        return Err(limit("prepared descriptions", options.max_prepared_bytes));
    }
    // Eagerly arm a complete source set only within the stage's active data
    // allocation. Larger source sets use bounded, drained capture epochs.
    if !admission.many_interfaces && admission.interfaces.len() <= source_ceiling {
        // Preflight sources are acquisition hints, not current route authority.
        // Include every freshly admitted source before deciding whether the
        // complete set fits this stage's active capture allocation.
        let mut interfaces = Vec::with_capacity(source_ceiling);
        for interface in &plan.interfaces {
            interfaces.push(interface.clone());
        }
        let mut fits = true;
        for interface in &admission.interfaces {
            if interfaces
                .iter()
                .any(|current| current.index == interface.index)
            {
                continue;
            }
            if interfaces.len() == source_ceiling {
                fits = false;
                break;
            }
            interfaces.push(interface.clone());
        }
        if !interfaces.is_empty() && fits {
            plan.interfaces = interfaces;
        }
    }
    let descriptions = initial
        .batches
        .into_iter()
        .map(|offer| {
            (
                offer.index,
                Descriptor {
                    batch: BatchStorage::Owned(offer.batch),
                    host_deadline: offer.host_deadline,
                    route: None,
                },
            )
        })
        .collect();
    let streaming = Streaming {
        done: initial.done,
        next_ready: initial.next_ready,
        max_probe_bytes: admission.max_probe_bytes,
        max_descriptor_bytes: descriptor_bytes,
        max_source_name_bytes: admission.max_source_name_bytes,
    };
    let mut pipeline = Pipeline::assemble(
        executor,
        options,
        deadline,
        started,
        Output::Stream(feed),
        history,
        InitialState {
            plan,
            descriptions,
            streaming: Some(streaming),
        },
    )?;
    let result = pipeline.drive();
    pipeline.finish(result)
}

/// Admits `batches` as [`run`] would and keeps nothing, so a stage over its
/// preparation limit fails before anything is sent.
pub(super) fn admit<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
) -> Result<(), BoundaryError> {
    validate_options(batches, options)?;
    let deadline = executor
        .client
        .now()
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let planned = batches
        .iter()
        .map(Planned::new)
        .collect::<Result<Vec<_>, _>>()?;
    let preparation = until(executor.client, deadline, &options.control);
    prepare::plan(executor, &planned, options, deadline, &preparation, false).map(drop)
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

impl AdaptiveAdmission {
    pub(in crate::scan) fn new(effective_wave: usize) -> Self {
        Self {
            interfaces: Vec::new(),
            window: effective_wave,
            many_interfaces: false,
            max_description_bytes: 0,
            max_route_bytes: 0,
            max_map_route_bytes: 0,
            source_metadata_bytes: 0,
            max_source_name_bytes: 0,
            max_probe_bytes: 0,
            summary_bytes: 0,
        }
    }

    pub(in crate::scan) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.interfaces
                    .capacity()
                    .saturating_mul(std::mem::size_of::<interface::Id>()),
            )
            .saturating_add(
                self.interfaces
                    .iter()
                    .map(|interface| interface.name.capacity())
                    .sum::<usize>(),
            )
    }

    pub(in crate::scan) fn reserve_summaries(&mut self, bytes: usize) {
        self.summary_bytes = bytes;
    }

    pub(in crate::scan) fn check(
        &self,
        wave_len: usize,
        host_count: usize,
        options: &PipelineOptions,
    ) -> Result<(), BoundaryError> {
        if self.window == 0 {
            return Ok(());
        }
        let window =
            wave_len
                .min(options.max_in_flight)
                .min(self.window)
                .min(if self.many_interfaces {
                    capture::MAX_SOURCES
                } else {
                    usize::MAX
                });
        let sources = window.min(capture::MAX_SOURCES);
        let descriptor = self
            .max_description_bytes
            .saturating_add(self.max_route_bytes)
            .saturating_add(512);
        let source_names = source_charge(
            sources,
            self.max_source_name_bytes,
            self.source_metadata_bytes,
        );
        let bound = correlation::index_charge(window.saturating_mul(2), sources)
            .saturating_add(expiry::charge(window))
            .saturating_add(window.saturating_mul(2).saturating_mul(descriptor))
            .saturating_add(
                window
                    .min(host_count)
                    .saturating_mul(self.max_map_route_bytes),
            )
            .saturating_add(source_names)
            .saturating_add(self.max_probe_bytes)
            .saturating_add(self.summary_bytes);
        if bound > options.max_prepared_bytes {
            return Err(limit("prepared descriptions", options.max_prepared_bytes));
        }
        Ok(())
    }
}

fn source_charge(sources: usize, name_bytes: usize, metadata: usize) -> usize {
    // A closed epoch retains four names per source while the next interface
    // list, group request and partitioned requests are constructed. New native
    // sessions are armed only after assigning/dropping the old group.
    sources.saturating_mul(name_bytes.saturating_mul(7).saturating_add(metadata))
}

fn source_metadata<P: CaptureProviders>() -> usize {
    // Group::new allocates the next Owned<C> array before assignment drops
    // the old group. Include inline custom sessions and field/alignment slack,
    // even though the new session slots are not initialized until arm().
    let alignment =
        std::mem::align_of::<CaptureSession<P>>().max(std::mem::align_of::<capture::Source>());
    let owned = std::mem::size_of::<CaptureSession<P>>()
        .saturating_add(std::mem::size_of::<capture::Source>())
        .saturating_add(alignment.saturating_mul(2))
        .saturating_add(16);
    owned
        .saturating_add(std::mem::size_of::<capture::Request>())
        .saturating_mul(2)
        .saturating_add(std::mem::size_of::<capture::Metadata>())
        .saturating_add(std::mem::size_of::<interface::Id>().saturating_mul(3))
        .saturating_add(512)
}

pub(super) fn admit_adaptive<P: PacketProviders, K: Clock>(
    executor: &ExchangeExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
    summary: &mut AdaptiveAdmission,
) -> Result<(), BoundaryError> {
    summary.source_metadata_bytes = source_metadata::<P>();
    validate_options(batches, options)?;
    let deadline = executor
        .client
        .now()
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let planned = batches
        .iter()
        .map(Planned::new)
        .collect::<Result<Vec<_>, _>>()?;
    for planned in &planned {
        let scope_bytes = planned
            .probe
            .scope
            .as_ref()
            .map_or(0, crate::target::ResolvedZone::retained_bytes);
        summary.max_description_bytes = summary
            .max_description_bytes
            .max(384usize.saturating_add(scope_bytes));
    }
    let preparation = until(executor.client, deadline, &options.control);
    let plan = prepare::plan(executor, &planned, options, deadline, &preparation, false)?;
    let previous_summary_bytes = summary.retained_bytes();
    for ((_, scope), route) in &plan.routes {
        summary.max_route_bytes = summary.max_route_bytes.max(prepare::route_charge(route));
        summary.max_map_route_bytes = summary.max_map_route_bytes.max(
            prepare::route_charge(route)
                .saturating_add(scope.as_ref().map_or(0, |scope| scope.name.capacity())),
        );
        summary.max_source_name_bytes = summary
            .max_source_name_bytes
            .max(route.interface().name.len());
    }
    for probe in &plan.probes {
        summary.max_probe_bytes = summary.max_probe_bytes.max(probe.memory);
    }
    if !summary.many_interfaces {
        for interface in &plan.interfaces {
            if !summary.interfaces.contains(interface) {
                if summary.interfaces.len() == summary.window.min(capture::MAX_SOURCES) {
                    // More sources than the active allocation: a scalar sentinel
                    // replaces historical names instead of accumulating a cache.
                    summary.interfaces.clear();
                    summary.many_interfaces = true;
                    break;
                }
                // The caller already reserved the old summary. Charge each
                // additional name and the fixed table before copying it while
                // this temporary admission plan is still resident.
                let capacity_bytes = if summary.interfaces.capacity() == 0 {
                    summary
                        .window
                        .min(capture::MAX_SOURCES)
                        .saturating_mul(std::mem::size_of::<interface::Id>())
                } else {
                    0
                };
                let growth = summary
                    .retained_bytes()
                    .saturating_sub(previous_summary_bytes)
                    .saturating_add(capacity_bytes)
                    .saturating_add(interface.name.len());
                if plan
                    .base_bytes
                    .saturating_add(summary.max_probe_bytes)
                    .saturating_add(growth)
                    > options.max_prepared_bytes
                {
                    return Err(limit("prepared summaries", options.max_prepared_bytes));
                }
                if summary.interfaces.capacity() == 0 {
                    summary
                        .interfaces
                        .reserve_exact(summary.window.min(capture::MAX_SOURCES));
                }
                summary.interfaces.push(interface.clone());
            }
        }
    }
    drop(plan);
    Ok(())
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

    /// Completes the probes past their timeout once the capture queues have
    /// been drained, and reports whether they are still being drained.
    fn settle_expired(&mut self) -> Result<bool, BoundaryError> {
        if self.deadlines.notice_expired(self.executor.client.now()) {
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        // A callback can consume another probe's timeout while its reply is
        // already queued. Keep due probes until the bounded queues are drained.
        let draining_captures = self.deadlines.is_draining() && self.capture_drain_remaining > 0;
        if !draining_captures {
            while let Some(index) = self.deadlines.pop_expired() {
                self.complete(index)?;
            }
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        Ok(draining_captures)
    }

    /// Refill is called between cooperative capture boundaries, never from a
    /// publication thread. One controller remains the scheduling authority.
    fn refill(&mut self, draining: bool) -> Result<(), BoundaryError> {
        if draining
            || self.streaming.is_none()
            || self.pending.len().saturating_add(self.ready.len()) >= self.options.max_in_flight
            || self.executor.client.now() < self.next_send
        {
            return Ok(());
        }
        if self
            .streaming
            .as_ref()
            .and_then(|stream| stream.next_ready)
            .is_some_and(|ready| ready > self.executor.client.now())
        {
            return Ok(());
        }
        let maximum = self
            .streaming
            .as_ref()
            .expect("streaming checked")
            .max_probe_bytes;
        while self.retained.saturating_add(maximum) > self.options.max_prepared_bytes
            && self.retire_recent()
        {}
        if self.retained.saturating_add(maximum) > self.options.max_prepared_bytes {
            for probe in self.ready.values_mut().rev() {
                if self.retained.saturating_add(maximum) <= self.options.max_prepared_bytes {
                    break;
                }
                if let Some(preview) = probe.retained.take() {
                    drop(preview);
                    self.retained -= probe.memory;
                }
            }
        }
        let room = self
            .options
            .max_prepared_bytes
            .saturating_sub(self.retained);
        let capacity = self
            .options
            .max_in_flight
            .saturating_sub(self.pending.len().saturating_add(self.ready.len()))
            .min(room / maximum.max(1));
        if capacity == 0 {
            if self.pending.is_empty() {
                return Err(limit(
                    "prepared descriptions",
                    self.options.max_prepared_bytes,
                ));
            }
            return Ok(());
        }
        let Output::Stream(feed) = &mut self.output else {
            unreachable!("streaming output")
        };
        let poll = feed.poll(capacity, self.executor.client.now())?;
        if poll.batches.len() > capacity {
            return Err(limit("stream window", capacity));
        }
        let selected = poll.batches.len();
        let stream = self.streaming.as_mut().expect("streaming checked");
        stream.done = poll.done;
        stream.next_ready = poll.next_ready;
        for offer in poll.batches {
            if self.descriptions.contains_key(&offer.index) {
                return Err(limit("stream attempt identity", crate::scan::MAX_PROBES));
            }
            let probe = offer.batch.probe()?;
            let keep = self
                .retained
                .saturating_add(maximum.saturating_mul(selected.saturating_add(1)))
                <= self.options.max_prepared_bytes;
            let (route, mut admitted) =
                prepare::admit_one(&mut self.plan, probe, self.options.max_prepared_bytes, keep)?;
            let actual_description = 512usize
                .saturating_add(
                    probe
                        .scope
                        .as_ref()
                        .map_or(0, crate::target::ResolvedZone::retained_bytes),
                )
                .saturating_add(prepare::route_charge(&route));
            if admitted.memory > maximum
                || route.interface().name.len()
                    > self
                        .streaming
                        .as_ref()
                        .expect("streaming checked")
                        .max_source_name_bytes
                || actual_description
                    > self
                        .streaming
                        .as_ref()
                        .expect("streaming checked")
                        .max_descriptor_bytes
            {
                return Err(limit(
                    "changed prepared descriptions",
                    self.options.max_prepared_bytes,
                ));
            }
            if admitted.retained.is_some()
                && self
                    .retained
                    .saturating_add(admitted.memory)
                    .saturating_add(maximum)
                    > self.options.max_prepared_bytes
            {
                drop(admitted.retained.take());
            }
            if admitted.retained.is_some() {
                self.retained += admitted.memory;
            }
            if self.plan.interfaces.contains(route.interface()) {
                self.armed_ready.insert(offer.index);
            }
            if let Some(deadline) = offer.host_deadline {
                self.ready_deadlines.insert((deadline, offer.index));
            }
            self.descriptions.insert(
                offer.index,
                Descriptor {
                    batch: BatchStorage::Owned(offer.batch),
                    host_deadline: offer.host_deadline,
                    route: Some(Box::new(route)),
                },
            );
            self.ready.insert(offer.index, admitted);
        }
        self.rotate_if_needed()
    }

    fn rotate_if_needed(&mut self) -> Result<(), BoundaryError> {
        // Fixed pipelines arm every source up front; their ready queue can span
        // the whole stage, so rediscovering rotations here would be quadratic.
        if self.streaming.is_none() {
            return Ok(());
        }
        let changes = self.ready.iter().any(|(index, _)| {
            self.descriptions[index]
                .route
                .as_ref()
                .is_some_and(|route| !self.plan.interfaces.contains(route.interface()))
        });
        if !changes {
            return Ok(());
        }
        // Every active interval finishes in its original capture epoch. Only
        // unstarted work crosses the rearm boundary, so no negative interval
        // spans an unobserved cleanup/activation gap.
        if !self.pending.is_empty() {
            return Ok(());
        }
        self.close_group()?;
        while self.retire_recent() {}
        let mut interfaces =
            Vec::with_capacity(self.options.max_in_flight.min(capture::MAX_SOURCES));
        for index in self.ready.keys() {
            let descriptor = &self.descriptions[index];
            let probe = descriptor.probe();
            let route = descriptor.route.as_deref().unwrap_or_else(|| {
                &self.plan.routes[&(
                    probe.address,
                    probe.scope.as_ref().map(|scope| scope.interface.clone()),
                )]
            });
            if !interfaces.contains(route.interface()) {
                interfaces.push(route.interface().clone());
            }
        }
        let request = GroupRequest {
            interfaces: interfaces.clone(),
            limits: self.executor.collection.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let group = Group::new(&request).map_err(BoundaryError::from_error)?;
        self.plan.interfaces = interfaces;
        self.group = group;
        self.group_accounted = false;
        let armed = self.group.arm(
            self.executor.client.providers.capture(),
            &until(self.executor.client, self.deadline, &self.options.control),
        );
        check(self.executor.client, self.deadline, &self.options.control)?;
        armed.map_err(BoundaryError::from_error)?;
        let ready = self.group.wait_ready(&until(
            self.executor.client,
            self.deadline,
            &self.options.control,
        ));
        check(self.executor.client, self.deadline, &self.options.control)?;
        ready.map_err(BoundaryError::from_error)?;
        self.armed_ready = self.ready.keys().copied().collect();
        self.capture_drain_limit = self
            .group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture sources")
            * self.group.sources().len();
        self.capture_drain_remaining = self.capture_drain_limit;
        self.seen = SeenFrames::new(self.options.max_evidence_frames);
        self.candidates = CandidateIndex::new(
            self.plan.interfaces.len(),
            self.options.max_in_flight.saturating_mul(2),
        );
        Ok(())
    }

    fn close_group(&mut self) -> Result<(), BoundaryError> {
        if self.group_accounted {
            return Ok(());
        }
        let shutdown = self.group.shutdown().map_err(BoundaryError::from_error);
        let accounted = self.account_group(shutdown.is_ok());
        shutdown.and(accounted)
    }

    fn account_group(&mut self, publish: bool) -> Result<(), BoundaryError> {
        if self.group_accounted {
            return Ok(());
        }
        let sources = self.group.snapshot();
        self.group_accounted = true;
        for source in &sources {
            self.stats.capture = self
                .stats
                .capture
                .checked_add(source.statistics)
                .ok_or_else(|| limit("capture statistics", usize::MAX))?;
            self.aggregate_quality = self.aggregate_quality.combine(source.observation_quality);
        }
        if !publish {
            return Ok(());
        }
        for source in sources {
            if let Some(loss) = source.statistics.evidence_loss_error() {
                if source.limits.overflow_policy == capture::OverflowPolicy::Fail {
                    return Err(BoundaryError::from_error(loss));
                }
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "capture.evidence_incomplete",
                        format!(
                            "source {} on interface {} (index {}): {loss}",
                            source.index,
                            source.metadata.interface.name,
                            source.metadata.interface.index
                        ),
                    )))?;
            }
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.streaming.as_ref().is_none_or(|stream| stream.done)
    }

    fn retire_recent(&mut self) -> bool {
        let Some((index, _, charge)) = self.recent.pop_front() else {
            return false;
        };
        self.candidates.remove(index);
        self.recent_sent.remove(&index);
        self.retire_description(index);
        self.retained -= charge;
        true
    }

    fn retire_description(&mut self, index: usize) {
        drop(self.descriptions.remove(&index));
    }

    fn send_ready(&mut self, draining_captures: bool) -> Result<(), BoundaryError> {
        let now = self.executor.client.now();
        while self
            .ready_deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let (_, index) = self
                .ready_deadlines
                .pop_first()
                .expect("due queued attempt");
            if let Some(admitted) = self.ready.remove(&index) {
                self.armed_ready.remove(&index);
                let preview = if admitted.retained.is_some() {
                    admitted.memory
                } else {
                    0
                };
                drop(admitted);
                self.retained -= preview;
                self.omit(index)?;
            }
        }
        self.rotate_if_needed()?;
        while !draining_captures
            && self.pending.len() < self.options.max_in_flight
            && self.executor.client.now() >= self.next_send
        {
            let Some(index) = self
                .armed_ready
                .iter()
                .copied()
                .find(|index| !self.reply_overlaps(*index))
            else {
                break;
            };
            while self.ready.get(&index).is_some_and(|probe| {
                self.retained.saturating_add(probe.memory) > self.options.max_prepared_bytes
            }) && self.retire_recent()
            {}
            if self.retained.saturating_add(self.ready[&index].memory)
                > self.options.max_prepared_bytes
            {
                break;
            }
            let admitted = self.ready.remove(&index).expect("armed attempt is queued");
            self.armed_ready.remove(&index);
            if let Some(deadline) = self.descriptions[&index].host_deadline {
                self.ready_deadlines.remove(&(deadline, index));
            }
            self.send(index, admitted)?;
            if !self.spacing.is_zero() {
                break;
            }
        }
        Ok(())
    }

    fn reply_overlaps(&self, index: usize) -> bool {
        let next = self.descriptions[&index].probe();
        self.pending
            .keys()
            .any(|pending| replies_overlap(next, self.descriptions[pending].probe()))
    }

    fn omit(&mut self, index: usize) -> Result<(), BoundaryError> {
        self.failed_probe = None;
        self.retire_description(index);
        self.output.event(PipelineEvent::Omitted { index })?;
        if let Some(stream) = &mut self.streaming {
            stream.next_ready = None;
        }
        Ok(())
    }

    fn send(
        &mut self,
        index: usize,
        AdmittedProbe {
            cost,
            memory,
            retained,
        }: AdmittedProbe,
    ) -> Result<(), BoundaryError> {
        let client = self.executor.client;
        check(client, self.deadline, &self.options.control)?;
        let preview_bytes = if retained.is_some() { memory } else { 0 };
        let host_deadline = self.descriptions[&index].host_deadline;
        if host_deadline.is_some_and(|limit| client.now() >= limit) {
            drop(retained);
            self.retained -= preview_bytes;
            return self.omit(index);
        }
        let descriptor = &self.descriptions[&index];
        let timeout = descriptor.batch.batch().timeout;
        let probe = descriptor.probe();
        self.failed_probe = Some(probe.clone());
        let route = descriptor.route.as_deref().unwrap_or_else(|| {
            &self.plan.routes[&(
                probe.address,
                probe.scope.as_ref().map(|scope| scope.interface.clone()),
            )]
        });
        let prepared = match retained {
            Some(retained) => self
                .plan
                .admission
                .materialize_retained(retained, route, cost),
            None => self.plan.admission.rebuild(probe.packet(), route, cost),
        };
        self.retained -= preview_bytes;
        let prepared = prepared.map_err(|error| match error {
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
        check(client, self.deadline, &self.options.control)?;
        if host_deadline.is_some_and(|limit| client.now() >= limit) {
            drop(prepared);
            return self.omit(index);
        }
        self.stats.packets_attempted += 1;
        let sent = Arc::new(
            prepared
                .transmit(client.providers.transmit(), || Ok::<(), LiveIoError>(()))
                .map_err(BoundaryError::from_error)?,
        );
        self.stats.packets_completed += 1;
        self.history.sent(
            probe,
            &sent.built().packet,
            &sent.route().plan.decision.interface,
        );
        self.stats.bytes = self
            .stats
            .bytes
            .checked_add(sent.bytes_sent() as u64)
            .ok_or_else(|| limit("sent bytes", usize::MAX))?;
        let end = sent
            .timing()
            .freshness_marker()
            .monotonic()
            .checked_add(timeout)
            .ok_or_else(|| limit("probe timeout", max_wait_secs()))?
            .min(self.deadline);
        let end = host_deadline.map_or(end, |limit| end.min(limit));
        let source = self
            .plan
            .interfaces
            .iter()
            .position(|interface| *interface == sent.route().plan.decision.interface)
            .ok_or_else(|| limit("changed capture interface", capture::MAX_SOURCES))?;
        self.candidates.insert(
            index,
            source,
            &sent.built().packet,
            &self.executor.operation.registry,
        )?;
        self.deadlines.insert(end, index);
        self.pending.insert(
            index,
            Pending {
                sent: sent.clone(),
                deadline: end,
                best: None,
                passed: Vec::new(),
                last_response: None,
                charge: memory,
            },
        );
        self.retained += memory;
        self.output.event(PipelineEvent::Sent { index, sent })?;
        self.qualification = Some(match self.qualification {
            Some((stage, first, last)) => {
                (stage, first.min(probe.sequence), last.max(probe.sequence))
            }
            None => (probe.stage, probe.sequence, probe.sequence),
        });
        self.failed_probe = None;
        self.next_send = client
            .now()
            .checked_add(self.spacing)
            .ok_or_else(|| limit("pacing delay", max_wait_secs()))?;
        Ok(())
    }

    fn wake_time(&mut self) -> Instant {
        let mut earliest = self
            .deadlines
            .next()
            .unwrap_or(self.deadline)
            .min(self.deadline);
        if let Some((deadline, _)) = self.ready_deadlines.first() {
            earliest = earliest.min(*deadline);
        }
        let can_send = self
            .armed_ready
            .iter()
            .copied()
            .find(|index| !self.reply_overlaps(*index))
            .is_some_and(|index| {
                self.retained.saturating_add(self.ready[&index].memory)
                    <= self.options.max_prepared_bytes
            });
        let can_refill = self.streaming.as_ref().is_some_and(|stream| {
            !stream.done
                && self.pending.len().saturating_add(self.ready.len()) < self.options.max_in_flight
                && self.retained.saturating_add(stream.max_probe_bytes)
                    <= self.options.max_prepared_bytes
        });
        if self.pending.len() < self.options.max_in_flight && can_send {
            earliest = earliest.min(self.next_send);
        }
        if can_refill {
            let ready = self
                .streaming
                .as_ref()
                .and_then(|stream| stream.next_ready)
                .unwrap_or(self.next_send)
                .max(self.next_send);
            earliest = earliest.min(ready);
        }
        earliest
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
        let wait = Deadline::new(wait)
            .with_cancellation(self.executor.client.cancellation.clone())
            .with_parent(Some(Arc::new(self.options.control.clone())));
        let captured = self.group.next_captured_frame(&wait);
        check(self.executor.client, self.deadline, &self.options.control)?;
        let captured = captured.map_err(BoundaryError::from_error)?;
        if captured.is_none() && draining_captures {
            self.capture_drain_remaining = 0;
        }
        Ok(captured)
    }

    fn ingest(&mut self, captured: capture::Captured) -> Result<(), BoundaryError> {
        self.ingress_unknown |= captured.received_at.is_none();
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
                    self.output
                        .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                            "scan.decode_error",
                            packetcraftr_core::error::render(&error),
                        )))?;
                }
                self.output.event(PipelineEvent::Undecoded { frame: raw })?;
                return Ok(());
            }
        };
        if decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            if self.diagnostics.insert("integrity") {
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.integrity_rejected",
                        "checksum-invalid capture was not correlated",
                    )))?;
            }
            return Ok(());
        }
        let Some(received) = captured.received_at else {
            if self.diagnostics.insert("ingress") {
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "capture.ingress_time_unavailable",
                        "capture lacks a monotonic ingress marker and was not correlated",
                    )))?;
            }
            return Ok(());
        };
        let possible = self.candidates.lookup(source, &decoded.packet);
        let mut candidates = indexed_candidates(
            &possible,
            &self.pending,
            |index| self.descriptions.get(&index).map(Descriptor::probe),
            &self.executor.operation.registry,
            &decoded,
            &self.plan.interfaces[source],
            received,
        );

        if candidates.is_empty() {
            // Pending probes whose window closed have not settled yet, but
            // a frame after their deadline cannot be their outcome either.
            let settled = indexed_settled(
                &possible,
                |index| {
                    self.pending
                        .get(&index)
                        .filter(|entry| received > entry.deadline)
                        .map(|entry| &entry.sent)
                        .or_else(|| self.recent_sent.get(&index))
                },
                |index| self.descriptions.get(&index).map(Descriptor::probe),
                &self.executor.operation.registry,
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
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                        "scan.ambiguous_response",
                        "capture matched multiple pending probes and was not attributed",
                    )))?;
            }
            return self.unattributed(raw, Attribution::Ambiguous, None);
        }
        let (index, observation) = candidates.pop().expect("one candidate");
        if observation.response.reply == Reply::IpProtocolPayload
            && self.history.ambiguous(
                self.descriptions[&index].probe(),
                &decoded.packet,
                &self.plan.interfaces[source],
            )
        {
            if self.diagnostics.insert("ambiguous") {
                self.output.event(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.ambiguous_response",
                    "identity-less capture also matched a previous transmission and was not attributed",
                )))?;
            }
            return self.unattributed(raw, Attribution::Ambiguous, None);
        }
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
            let previous_bytes = entry
                .best
                .as_ref()
                .map(|previous| previous.response.response.frame.bytes().len());
            // Buffered duplicates may use spare capacity, but a winner takes priority.
            while let Err(error) = self.evidence.replace(
                previous_bytes,
                raw.bytes().len(),
                self.options.max_evidence_frames,
                self.options.max_evidence_bytes,
            ) {
                let Some(discarded) = self
                    .pending
                    .values_mut()
                    .find_map(|entry| entry.passed.pop())
                else {
                    return Err(match error {
                        RetentionError::FrameCountOverflow | RetentionError::FrameLimit => {
                            limit("evidence frames", self.options.max_evidence_frames)
                        }
                        RetentionError::ByteCountOverflow | RetentionError::ByteLimit => {
                            limit("evidence bytes", self.options.max_evidence_bytes)
                        }
                    });
                };
                self.evidence
                    .release(discarded.response.frame.bytes().len());
                self.evidence_limit()?;
            }
            let entry = self.pending.get_mut(&index).expect("candidate is pending");
            if let Some(previous) = entry.best.replace(candidate) {
                self.buffer_duplicate(index, previous.response)?;
            }
        } else {
            self.buffer_duplicate(index, candidate.response)?;
        }
        if definitive {
            self.complete(index)?;
        }
        Ok(())
    }

    fn buffer_duplicate(
        &mut self,
        index: usize,
        response: crate::exchange::Response,
    ) -> Result<(), BoundaryError> {
        if self
            .evidence
            .reserve(
                response.response.frame.bytes().len(),
                self.options.max_evidence_frames,
                self.options.max_evidence_bytes,
            )
            .is_ok()
        {
            self.pending
                .get_mut(&index)
                .expect("candidate is pending")
                .passed
                .push(response);
            Ok(())
        } else {
            self.evidence_limit()
        }
    }

    fn evidence_limit(&mut self) -> Result<(), BoundaryError> {
        if self.diagnostics.insert("scan.evidence_limit") {
            self.output
                .event(PipelineEvent::Diagnostic(Diagnostic::warning(
                    "scan.evidence_limit",
                    "scan evidence retention limit reached; extra replies were omitted",
                )))?;
        }
        Ok(())
    }

    fn unattributed(
        &mut self,
        frame: Frame,
        attribution: Attribution,
        index: Option<usize>,
    ) -> Result<(), BoundaryError> {
        let sequence = index.and_then(|index| {
            self.descriptions
                .get(&index)
                .map(|description| description.probe().sequence)
        });
        self.output.event(PipelineEvent::Unattributed {
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
        self.failed_probe = Some(self.descriptions[&index].probe().clone());
        let stats = Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: entry.sent.bytes_sent() as u64,
            elapsed: entry.sent.timing().freshness_marker().monotonic().elapsed(),
            capture: Default::default(),
        };
        let mut responses: Vec<_> = entry
            .best
            .take()
            .map(|best| best.response)
            .into_iter()
            .collect();
        responses.append(&mut entry.passed);
        for response in &responses {
            self.evidence.release(response.response.frame.bytes().len());
        }
        let execution = Evidence {
            observation_quality: None,
            permit: self.descriptions[&index].batch.batch().permit,
            sent: vec![entry.sent.as_ref().clone()],
            responses,
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats,
        };
        self.output
            .event(PipelineEvent::Completed { index, execution })?;
        let entry = self
            .pending
            .remove(&index)
            .expect("completed pending probe");
        if self.recent.len() == self.options.max_in_flight {
            self.retire_recent();
        }
        self.deadlines.remove(entry.deadline, index);
        self.recent_sent.insert(index, entry.sent.clone());
        self.recent.push_back((index, entry.sent, entry.charge));
        if let Some(stream) = &mut self.streaming {
            stream.next_ready = None;
        }
        self.failed_probe = None;
        Ok(())
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
