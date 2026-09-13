// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Passive live capture under one operation budget and readiness barrier.
//! Native session ownership stays in netio; this workflow assigns capture IDs,
//! applies policy before selection, and retains per-source completion evidence.

use crate::{Stats, policy::CaptureBudget};
use packetcraftr_core::{
    budget::Cancellation,
    diagnostic::Diagnostic,
    error::{BoundaryError, Classification, Classified, Coordinate, Kind},
    frame::Frame,
};
use packetcraftr_netio::{
    capture::{self as native, group},
    interface::Id,
};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Options {
    pub window: Duration,
    pub budget: CaptureBudget,
    pub cancellation: Option<Cancellation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Window,
    FrameBudget,
    Sink,
    Failure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    StopBefore,
    StopAfter,
}
#[derive(Clone, Debug)]
pub struct Source {
    pub capture: group::Source,
    pub admitted_frames: u64,
    pub matched_frames: u64,
    pub emitted_frames: u64,
    pub late_frames: u64,
}
#[derive(Clone, Debug)]
pub struct Report {
    pub requested_interfaces: Vec<Id>,
    pub sources: Vec<Source>,
    pub frames_delivered: u64,
    pub stats: Stats,
    pub budget: CaptureBudget,
    pub stop: StopReason,
    pub capture_statistics_complete: bool,
    pub diagnostics: Vec<Diagnostic>,
}
#[derive(Clone, Debug)]
pub enum Event {
    /// All admitted source metadata is available before the first frame. The
    /// zero-window case has activated metadata but does not claim readiness.
    Started { sources: Vec<group::Source> },
    Frame {
        source_frame: u64,
        source: usize,
        elapsed: Duration,
        frame: Frame,
    },
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Cause {
    #[error(transparent)]
    Native(Box<group::Error>),
    #[error(transparent)]
    Budget(#[from] crate::policy::Error),
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error("capture consumer failed: {0}")]
    Consumer(#[source] BoundaryError),
    #[error("invalid capture operation: {0}")]
    Invalid(&'static str),
    #[error("capture statistics cannot be combined without overflow")]
    Statistics,
    #[error("capture evidence was lost at source {source_index}: {error}")]
    Loss {
        source_index: usize,
        #[source]
        error: packetcraftr_netio::Error,
    },
}
impl Classified for Cause {
    fn classification(&self) -> Classification {
        match self {
            Self::Native(error) => error.classification(),
            Self::Budget(error) => error.classification(),
            Self::Cancelled(error) => error.classification(),
            Self::Consumer(error) => error.classification(),
            Self::Invalid(_) => Classification::new("cli.capture_options", Kind::Cli, None),
            Self::Statistics => {
                Classification::new("internal.capture_statistics", Kind::Internal, None)
            }
            Self::Loss { error, .. } => error.classification(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct Error {
    #[source]
    pub cause: Box<Cause>,
    pub report: Box<Report>,
    pub cleanup: Vec<group::Failure>,
    pub source_frame: Option<u64>,
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        self.cause.classification()
    }
    fn context(&self) -> Option<Coordinate> {
        self.source_frame.map(Coordinate::SourceFrame)
    }
    fn causes(&self) -> Vec<String> {
        let mut causes = packetcraftr_core::error::source_chain(self);
        causes.extend(self.cleanup.iter().map(ToString::to_string));
        causes
    }
}
/// Callbacks run synchronously and must cooperate with their own I/O bounds.
/// `StopBefore` records a matched but unpublished frame; `StopAfter` records a
/// published final frame. Every exit attempts shutdown of every admitted source.
/// A pre-spent budget remains shared; report statistics are deltas for this run.
pub fn run<P, S, F>(
    provider: &P,
    request: &group::Request,
    options: Options,
    mut select: S,
    mut emit: F,
) -> Result<Report, Error>
where
    P: native::Provider,
    S: FnMut(u64, &Frame) -> Result<bool, BoundaryError>,
    F: FnMut(Event) -> Result<Control, BoundaryError>,
{
    let started = Instant::now();
    let initial = options.budget;
    let validated = request.validate();
    let mut report = Report {
        requested_interfaces: if validated.is_ok() {
            request.interfaces.clone()
        } else {
            Vec::new()
        },
        sources: Vec::new(),
        frames_delivered: 0,
        stats: Stats::default(),
        budget: options.budget,
        stop: StopReason::Failure,
        capture_statistics_complete: false,
        diagnostics: Vec::new(),
    };
    if let Err(error) = validated {
        return Err(failure(Cause::Native(Box::new(error)), report, None));
    }
    if options.window > native::MAX_TIMEOUT || started.checked_add(options.window).is_none() {
        return Err(failure(
            Cause::Invalid("capture window exceeds the supported range"),
            report,
            None,
        ));
    }
    if let Some(signal) = &options.cancellation
        && let Err(error) = signal.check()
    {
        return Err(failure(Cause::Cancelled(error), report, None));
    }
    let mut group = match group::Group::arm(provider, request, options.cancellation.clone()) {
        Ok(group) => group,
        Err(error) => {
            replace_sources(&mut report, &error.sources);
            finish_stats(&mut report, initial, started);
            return Err(failure(Cause::Native(Box::new(error)), report, None));
        }
    };
    let deadline = started + options.window;
    let mut primary = None;
    let mut source_frame = None;
    if !options.window.is_zero() {
        match deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        {
            Some(remaining) => {
                if let Err(error) = group.wait_ready(remaining) {
                    primary = Some(Cause::Native(Box::new(error)));
                }
            }
            None => primary = Some(Cause::Invalid("capture window expired during activation")),
        }
    }
    replace_sources(&mut report, &group.snapshot());
    if primary.is_none() {
        match emit(Event::Started {
            sources: group.snapshot(),
        }) {
            Ok(Control::Continue) => {}
            Ok(Control::StopBefore | Control::StopAfter) => report.stop = StopReason::Sink,
            Err(error) => primary = Some(Cause::Consumer(error)),
        }
    }
    while primary.is_none() && report.stop != StopReason::Sink {
        if let Some(signal) = &options.cancellation
            && let Err(error) = signal.check()
        {
            primary = Some(Cause::Cancelled(error));
            break;
        }
        if report.budget.is_exhausted() {
            report.stop = StopReason::FrameBudget;
            break;
        }
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        else {
            report.stop = StopReason::Window;
            break;
        };
        let record = match group.next_record(remaining.min(Duration::from_millis(50))) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) => {
                source_frame = report.frames_delivered.checked_add(1);
                primary = Some(Cause::Native(Box::new(error)));
                break;
            }
        };
        let Some(number) = report.frames_delivered.checked_add(1) else {
            primary = Some(Cause::Statistics);
            break;
        };
        report.frames_delivered = number;
        source_frame = Some(number);
        if Instant::now() > deadline {
            report.sources[record.source].late_frames += 1;
            report.stop = StopReason::Window;
            source_frame = None;
            break;
        }
        let mut frame = record.captured.frame;
        frame.interface = Some(record.source as u32);
        if let Err(error) = report.budget.account(u64::from(frame.captured_length())) {
            primary = Some(Cause::Budget(error));
            break;
        }
        report.sources[record.source].admitted_frames += 1;
        match select(number, &frame) {
            Ok(true) => {}
            Ok(false) => {
                source_frame = None;
                continue;
            }
            Err(error) => {
                primary = Some(Cause::Consumer(error));
                break;
            }
        }
        report.sources[record.source].matched_frames += 1;
        match emit(Event::Frame {
            source_frame: number,
            source: record.source,
            elapsed: started.elapsed(),
            frame,
        }) {
            Ok(control) => {
                if control != Control::StopBefore {
                    report.sources[record.source].emitted_frames += 1;
                }
                if control != Control::Continue {
                    report.stop = StopReason::Sink;
                }
                source_frame = None;
            }
            Err(error) => {
                primary = Some(Cause::Consumer(error));
                break;
            }
        }
    }
    let mut cleanup = Vec::new();
    if let Some(Cause::Native(error)) = &primary {
        // Group failures already completed the entire shutdown attempt.
        replace_sources(&mut report, &error.sources);
    } else {
        match group.shutdown() {
            Ok(sources) => replace_sources(&mut report, &sources),
            Err(error) => {
                replace_sources(&mut report, &error.sources);
                if primary.is_none() {
                    primary = Some(Cause::Native(Box::new(error)));
                    source_frame = None;
                } else {
                    if let group::Cause::Provider(failure) = *error.cause {
                        cleanup.push(failure);
                    }
                    cleanup.extend(error.cleanup);
                }
            }
        }
    }
    if !finish_stats(&mut report, initial, started) && primary.is_none() {
        primary = Some(Cause::Statistics);
    }
    if primary.is_none() {
        for source in &report.sources {
            if let Some(error) = source.capture.statistics.evidence_loss_error() {
                if source.capture.limits.overflow_policy == native::OverflowPolicy::Fail {
                    primary = Some(Cause::Loss {
                        source_index: source.capture.index,
                        error,
                    });
                    break;
                }
                report.diagnostics.push(Diagnostic::warning(
                    "capture.evidence_incomplete",
                    format!(
                        "source {} ({}): {error}",
                        source.capture.index, source.capture.metadata.interface.name
                    ),
                ));
            }
        }
    }
    if let Some(cause) = primary {
        report.stop = StopReason::Failure;
        Err(Error {
            cause: Box::new(cause),
            report: Box::new(report),
            cleanup,
            source_frame,
        })
    } else {
        Ok(report)
    }
}
fn failure(cause: Cause, report: Report, source_frame: Option<u64>) -> Error {
    Error {
        cause: Box::new(cause),
        report: Box::new(report),
        cleanup: Vec::new(),
        source_frame,
    }
}
fn replace_sources(report: &mut Report, sources: &[group::Source]) {
    for source in sources {
        if let Some(existing) = report.sources.get_mut(source.index) {
            existing.capture = source.clone();
        } else {
            report.sources.push(Source {
                capture: source.clone(),
                admitted_frames: 0,
                matched_frames: 0,
                emitted_frames: 0,
                late_frames: 0,
            });
        }
    }
}
fn finish_stats(report: &mut Report, initial: CaptureBudget, started: Instant) -> bool {
    report.stats.packets_attempted = report.budget.frames() - initial.frames();
    report.stats.bytes = report.budget.bytes() - initial.bytes();
    report.stats.packets_completed = report
        .sources
        .iter()
        .map(|source| source.emitted_frames)
        .sum();
    report.stats.elapsed = started.elapsed();
    let mut capture = native::Statistics::default();
    let mut complete = report.sources.len() == report.requested_interfaces.len();
    for source in &report.sources {
        complete &= source.capture.metadata_valid
            && source.capture.shutdown_confirmed
            && source.capture.statistics_valid;
        if let Some(sum) = capture.checked_add(source.capture.statistics) {
            capture = sum;
        } else {
            report.capture_statistics_complete = false;
            return false;
        }
    }
    report.stats.capture = capture;
    report.capture_statistics_complete = complete;
    complete
}
