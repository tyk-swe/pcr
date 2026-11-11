// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod admission;
mod attempts;
mod capture_lifecycle;
mod correlation;
mod settlement;
mod streaming;
mod transmission;

pub(in crate::scan) use admission::AdaptiveAdmission;
pub(super) use admission::{admit, admit_adaptive};
pub(super) use streaming::run_stream;

mod expiry;
mod prepare;
use super::{PipelineEvent, PipelineFeed, PipelineOptions};
use crate::probe::Batch;
use crate::scan::{PipelineFailure, Probe};
use crate::{
    Client, Stats,
    clock::Clock,
    engine::execution::{limits::check_rate, rate_delay},
    evidence::RetentionBudget,
    exchange::WorkflowExecutor,
    providers::{CaptureProviders, PacketProviders},
};
use attempts::{Attempts, BatchStorage, Descriptor};
use capture_lifecycle::CaptureEpoch;
use packetcraftr_core::{
    budget::Deadline,
    decode::Dissector,
    error::{BoundaryError, Classification as ErrorClassification, Kind},
};
use packetcraftr_netio::{capture, deadline::MAX_WAIT, transmit::Provider as _};
use prepare::{AdmittedProbe, Plan, Planned};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

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
            check_rate::<crate::scan::Error>("probes_per_second", options.probes_per_second)
                .is_ok(),
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
        ErrorClassification::new(
            packetcraftr_core::error::Code::PolicyScanPipelineLimit,
            Kind::Policy,
            None,
        ),
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
            ErrorClassification::new(
                packetcraftr_core::error::Code::PolicyScanDurationLimit,
                Kind::Policy,
                None,
            ),
            Vec::new(),
        ));
    }
    Ok(())
}
pub(super) fn run<P: PacketProviders, K: Clock>(
    executor: &WorkflowExecutor<'_, P, K>,
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

type CaptureSession<P> = <<P as CaptureProviders>::Capture as capture::Provider>::Capture;

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

struct InitialState<'a, P: PacketProviders, K> {
    plan: Plan<'a, P, K>,
    descriptions: BTreeMap<usize, Descriptor<'a>>,
    streaming: Option<Streaming>,
    capture: CaptureEpoch<'a, P, K>,
}

struct Pipeline<'a, P: PacketProviders, K> {
    history: &'a mut super::reply_history::ReplyHistory,
    executor: &'a WorkflowExecutor<'a, P, K>,
    transmitter: Box<dyn packetcraftr_netio::transmit::Provider + 'a>,
    attempts: Attempts<'a>,
    streaming: Option<Streaming>,
    options: PipelineOptions,
    deadline: Instant,
    started: Instant,
    output: Output<'a>,
    plan: Plan<'a, P, K>,
    capture: CaptureEpoch<'a, P, K>,
    qualification: Option<(crate::scan::Stage, u64, u64)>,
    decoder: Dissector,
    spacing: Duration,
    stats: Stats,
    evidence: RetentionBudget,
    failed_probe: Option<Probe>,
    ingress_unknown: bool,
    diagnostics: HashSet<&'static str>,
    next_send: Instant,
}

impl<'a, P: PacketProviders, K: Clock> Pipeline<'a, P, K> {
    fn open(
        executor: &'a WorkflowExecutor<'a, P, K>,
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
        let capture = CaptureEpoch::open(
            executor,
            plan.interfaces.clone(),
            deadline,
            &options.control,
            options.max_evidence_frames,
        )?;
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
                capture,
            },
        )
    }

    fn assemble(
        executor: &'a WorkflowExecutor<'a, P, K>,
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
            capture,
        } = initial;
        let capacity = if streaming.is_some() {
            options.max_in_flight.saturating_mul(2)
        } else {
            descriptions
                .len()
                .min(options.max_in_flight.saturating_mul(2))
        };
        let attempts = Attempts::new(
            descriptions,
            std::mem::take(&mut plan.probes),
            capture.source_count(),
            capacity,
            options.max_in_flight,
            plan.base_bytes,
        );
        Ok(Self {
            history,
            executor,
            transmitter: executor.client.providers.transmit().session(),
            attempts,
            streaming,
            options,
            deadline,
            started,
            output,
            plan,
            capture,
            qualification: None,
            decoder: Dissector::new(executor.operation.registry.clone()),
            spacing: Duration::ZERO,
            stats: Stats::default(),
            evidence: RetentionBudget::default(),
            failed_probe: None,
            ingress_unknown: false,
            diagnostics: HashSet::new(),
            next_send: started,
        })
    }

    fn account_capture(
        stats: &mut Stats,
        output: &mut Output<'_>,
        publish: bool,
        sources: &[capture::Source],
    ) -> Result<(), BoundaryError> {
        for source in sources {
            stats.capture = stats
                .capture
                .checked_add(source.statistics)
                .ok_or_else(|| limit("capture statistics", usize::MAX))?;
        }
        if !publish {
            return Ok(());
        }
        for source in sources {
            if let Some(loss) = source.statistics.evidence_loss_error() {
                if source.limits.overflow_policy == capture::OverflowPolicy::Fail {
                    return Err(BoundaryError::from_error(loss));
                }
                output.event(PipelineEvent::Diagnostic(
                    packetcraftr_core::diagnostic::Diagnostic::new(
                        packetcraftr_core::diagnostic::Severity::Warning,
                        packetcraftr_core::error::Code::CaptureEvidenceIncomplete.as_str(),
                        format!(
                            "source {} on interface {} (index {}): {loss}",
                            source.index,
                            source.metadata.interface.name,
                            source.metadata.interface.index
                        ),
                    ),
                ))?;
            }
        }
        Ok(())
    }

    /// Runs the scan to completion or first failure. The caller passes the
    /// result to [`Self::finish`] either way.
    fn drive(&mut self) -> Result<(), BoundaryError> {
        check(self.executor.client, self.deadline, &self.options.control)?;
        self.capture.ready()?;
        self.spacing = rate_delay::<crate::scan::Error>(
            "probes_per_second",
            1,
            self.options.probes_per_second,
        )
        .map_err(BoundaryError::from_error)?;
        self.next_send = self.executor.client.now();
        while !self.done()
            || self.attempts.queued_count() != 0
            || self.attempts.pending_count() != 0
        {
            check(self.executor.client, self.deadline, &self.options.control)?;
            let draining_captures = self.settle_expired()?;
            self.refill(draining_captures)?;
            self.send_ready(draining_captures)?;
            if self.done()
                && self.attempts.queued_count() == 0
                && self.attempts.pending_count() == 0
            {
                break;
            }
            let wake = self.wake_time();
            let Some(captured) = self.capture.read_frame(wake, draining_captures)? else {
                continue;
            };
            self.ingest(captured)?;
        }
        check(self.executor.client, self.deadline, &self.options.control)
    }

    fn finish(mut self, result: Result<(), BoundaryError>) -> Result<Stats, BoundaryError> {
        let capture_lifecycle = self.capture;
        let capture = capture_lifecycle.finish(result.is_ok(), &mut |publish, sources| {
            Self::account_capture(&mut self.stats, &mut self.output, publish, sources)
        });
        let mut result = result;
        let mut cleanup = None;
        if let Some(error) = capture.shutdown {
            if result.is_ok() {
                result = Err(BoundaryError::from_error(error));
            } else {
                cleanup = Some(Box::new(error));
            }
        }
        if let Err(error) = capture.accounted
            && result.is_ok()
        {
            result = Err(error);
        }
        let capture_sources = capture.sources;
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
            let quality = capture.quality;
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
            pending: self.attempts.pending_evidence(),
            failed_probe: self.failed_probe,
            capture_sources,
            cleanup,
        }))
    }
}

#[cfg(test)]
mod tests;
