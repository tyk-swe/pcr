// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A capture group: one composite [`Session`] with bounded ownership,
//! readiness, and fair delivery across selected interfaces. Queue limits are
//! partitioned across sources; each source keeps its native metadata and
//! records. Workflow/file layers choose capture-global output IDs.

use super::{
    Captured, Limits, Metadata, NativeSettings, Provider, Realized, RealizedSettings, Request,
    Session, Statistics,
};
use crate::{Error, interface::Id};
use packetcraftr_core::{budget::Deadline, frame::LinkType};
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

/// Most interfaces one [`Group`] captures from.
pub const MAX_SOURCES: usize = 16;
const POLL_SLICE: Duration = Duration::from_millis(5);

/// Configuration for a [`Group`]: the shared queue limits are partitioned
/// across `interfaces`, and every source gets the same filter and settings.
#[derive(Clone, Debug)]
pub struct GroupRequest {
    pub interfaces: Vec<Id>,
    pub limits: Limits,
    pub filter: Option<String>,
    pub promiscuous: bool,
    /// Optional native-driver settings applied to every source; each session
    /// reports its own realized values.
    pub native: NativeSettings,
}

impl GroupRequest {
    /// Validate the complete set before arming anything: the filter limit a
    /// single session applies, the source count, the shared limits, distinct
    /// interfaces, and room for one full snapshot in every source.
    pub fn validate(&self) -> Result<(), Error> {
        super::validate_filter_length(self.filter.as_deref())?;
        let count = self.interfaces.len();
        if count == 0 || count > MAX_SOURCES {
            return Err(invalid("select 1..=16 capture interfaces"));
        }
        self.limits.validate()?;
        self.native.validate(&self.limits)?;
        let mut identities = HashSet::new();
        for interface in &self.interfaces {
            if interface.name.len() > 4096 || !identities.insert(interface.index) {
                return Err(invalid("interface identities must be distinct and bounded"));
            }
        }
        if self.limits.max_frames < count || self.limits.max_bytes / count < self.limits.snap_length
        {
            return Err(invalid(
                "shared queues must hold at least one full snapshot per interface",
            ));
        }
        Ok(())
    }

    /// Splits both queue ceilings exactly, retaining a full snapshot's
    /// capacity in every source. Callers validate first.
    fn partition(&self) -> Vec<Request> {
        let count = self.interfaces.len();
        self.interfaces
            .iter()
            .enumerate()
            .map(|(index, interface)| Request {
                interface: interface.clone(),
                limits: Limits {
                    max_frames: self.limits.max_frames / count
                        + usize::from(index < self.limits.max_frames % count),
                    max_bytes: self.limits.max_bytes / count
                        + usize::from(index < self.limits.max_bytes % count),
                    ..self.limits
                },
                filter: self.filter.clone(),
                promiscuous: self.promiscuous,
                native: self.native.clone(),
            })
            .collect()
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidCaptureGroup { reason }
}

/// The group operation during which a source failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Arm,
    Ready,
    Receive,
    Shutdown,
    Statistics,
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Arm => "arming",
            Self::Ready => "readiness",
            Self::Receive => "receive",
            Self::Shutdown => "shutdown",
            Self::Statistics => "statistics",
        })
    }
}

/// What a group knows about one admitted source.
#[derive(Clone, Debug)]
pub struct Source {
    pub index: usize,
    pub metadata: Metadata,
    pub limits: Limits,
    pub metadata_valid: bool,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: Statistics,
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
}

struct Owned<C: Session> {
    capture: C,
    source: Source,
    shutdown_attempted: bool,
}

/// Reported by [`Session::metadata`] for a group that admitted no source,
/// because arming failed at its first interface or never ran. It names no
/// interface and holds no snapshot.
static UNARMED: Metadata = Metadata {
    interface: Id {
        name: String::new(),
        index: 0,
    },
    link_type: LinkType(0),
    snap_length: 0,
    native: RealizedSettings {
        buffer_size: Realized {
            requested: None,
            applied: None,
            effective: None,
        },
        timestamp_source: Realized {
            requested: None,
            applied: None,
            effective: None,
        },
        timestamp_precision: Realized {
            requested: None,
            applied: None,
            effective: None,
        },
    },
};

/// A composite [`Session`] over one provider session per interface.
///
/// Create it with [`Group::new`], then [`Group::arm`] it. Arming and every
/// wait take the caller's [`Deadline`], whose cancellation stops the group
/// (see the [deadline convention](crate::deadline)). Any failure shuts
/// down every admitted source at once; [`Group::snapshot`] stays readable
/// afterwards, including after an arming failure, and [`Session::shutdown`]
/// then reports the cleanup failures. Every admitted session is shut down
/// exactly once. Drop attempts remaining cleanup but cannot report errors;
/// callers should explicitly call `shutdown`.
pub struct Group<C: Session> {
    requests: Vec<Request>,
    sources: Vec<Owned<C>>,
    cleanup: Vec<Error>,
    cursor: usize,
    armed: bool,
    ready: bool,
    closed: bool,
}

impl<C: Session> Group<C> {
    /// Validates `request` and partitions its limits; arms nothing yet.
    pub fn new(request: &GroupRequest) -> Result<Self, Error> {
        request.validate()?;
        let requests = request.partition();
        Ok(Self {
            sources: Vec::with_capacity(requests.len()),
            requests,
            cleanup: Vec::new(),
            cursor: 0,
            armed: false,
            ready: false,
            closed: false,
        })
    }

    /// Arms one provider session per interface, in request order, and checks
    /// each one's activation metadata against its request. Every provider call
    /// receives the caller's `deadline`. A failure shuts down every source
    /// admitted so far.
    pub fn arm<P: Provider<Capture = C>>(
        &mut self,
        provider: &P,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        if self.armed || self.closed {
            return Err(self.fail(Error::CaptureGroupState));
        }
        self.armed = true;
        for index in 0..self.requests.len() {
            if let Err(error) = check_cancelled(deadline) {
                return Err(self.fail(error));
            }
            let request = &self.requests[index];
            let capture = match provider.arm_capture(request, deadline) {
                Ok(capture) => capture,
                Err(source) => {
                    let failure = Error::CaptureSource {
                        index,
                        interface: request.interface.clone(),
                        phase: Phase::Arm,
                        source: Box::new(source),
                    };
                    return Err(self.fail(failure));
                }
            };
            let metadata = capture.metadata();
            let native = &metadata.native;
            let valid = capture.source_count() == 1
                && metadata.interface == request.interface
                && metadata.snap_length > 0
                && metadata.snap_length <= request.limits.snap_length
                && native
                    .buffer_size
                    .consistent_with(request.native.buffer_size)
                && native
                    .timestamp_source
                    .consistent_with(request.native.timestamp_source)
                && native
                    .timestamp_precision
                    .consistent_with(request.native.timestamp_precision);
            // Keep reported identity even on a contract failure, while bounding
            // an injected provider's invalid name before copying it.
            let reported_name = if metadata.interface.name.len() > 4096 {
                format!(
                    "{}... [truncated]",
                    metadata
                        .interface
                        .name
                        .chars()
                        .take(512)
                        .collect::<String>()
                )
            } else {
                metadata.interface.name.clone()
            };
            let metadata = Metadata {
                interface: Id {
                    index: metadata.interface.index,
                    name: reported_name,
                },
                link_type: metadata.link_type,
                snap_length: metadata.snap_length,
                native: metadata.native,
            };
            let limits = request.limits;
            self.sources.push(Owned {
                capture,
                source: Source {
                    index,
                    metadata,
                    limits,
                    metadata_valid: valid,
                    ready: false,
                    shutdown_confirmed: false,
                    statistics_valid: false,
                    statistics: Statistics::default(),
                    delivered_frames: 0,
                    delivered_bytes: 0,
                },
                shutdown_attempted: false,
            });
            if !valid {
                return Err(self.fail(Error::CaptureSourceContract {
                    index,
                    reason: "activation metadata disagrees with the request",
                }));
            }
        }
        Ok(())
    }

    /// Every admitted source, in source order.
    pub fn sources(&self) -> impl ExactSizeIterator<Item = &Source> {
        self.sources.iter().map(|source| &source.source)
    }

    /// Every admitted source with its current statistics; final after
    /// shutdown, and still readable after any failure.
    pub fn snapshot(&self) -> Vec<Source> {
        self.sources
            .iter()
            .map(|owned| {
                let mut source = owned.source.clone();
                if !owned.shutdown_attempted {
                    source.statistics = owned.capture.statistics();
                    source.statistics_valid = source.statistics.validate().is_ok();
                }
                source
            })
            .collect()
    }

    fn poll(
        &mut self,
        index: usize,
        wait: &Deadline,
        caller: &Deadline,
    ) -> Result<Option<Captured>, Error> {
        let mut captured = match self.sources[index].capture.next_captured_frame(wait) {
            Ok(Some(captured)) => captured,
            Ok(None) => return Ok(None),
            Err(source) => {
                let failure = self.failure(index, Phase::Receive, source);
                return Err(self.fail(failure));
            }
        };
        if let Err(error) = check_cancelled(caller) {
            return Err(self.fail(error));
        }
        let source = &mut self.sources[index].source;
        if captured.frame.link_type != source.metadata.link_type
            || captured.frame.bytes().len() > source.metadata.snap_length
            || captured
                .frame
                .interface
                .is_some_and(|interface| interface != source.metadata.interface.index)
        {
            return Err(self.fail(Error::CaptureSourceContract {
                index,
                reason: "captured frame disagrees with activated source metadata",
            }));
        }
        let (Some(frames), Some(bytes)) = (
            source.delivered_frames.checked_add(1),
            source
                .delivered_bytes
                .checked_add(u64::from(captured.frame.captured_length())),
        ) else {
            return Err(self.fail(Error::CaptureSourceContract {
                index,
                reason: "delivery counters overflowed",
            }));
        };
        source.delivered_frames = frames;
        source.delivered_bytes = bytes;
        captured.source = index;
        Ok(Some(captured))
    }

    fn failure(&self, index: usize, phase: Phase, source: Error) -> Error {
        Error::CaptureSource {
            index,
            interface: self.sources[index].source.metadata.interface.clone(),
            phase,
            source: Box::new(source),
        }
    }

    /// Shuts every source down, keeps the cleanup failures for
    /// [`Session::shutdown`], and returns `error`.
    fn fail(&mut self, error: Error) -> Error {
        self.shutdown_all();
        error
    }

    fn shutdown_all(&mut self) {
        self.closed = true;
        self.ready = false;
        for owned in &mut self.sources {
            if owned.shutdown_attempted {
                continue;
            }
            owned.shutdown_attempted = true;
            let interface = &owned.source.metadata.interface;
            let failure = |phase, source| Error::CaptureSource {
                index: owned.source.index,
                interface: interface.clone(),
                phase,
                source: Box::new(source),
            };
            match owned.capture.shutdown() {
                Ok(()) => owned.source.shutdown_confirmed = true,
                Err(source) => self.cleanup.push(failure(Phase::Shutdown, source)),
            }
            owned.source.statistics = owned.capture.statistics();
            match owned.source.statistics.validate() {
                Ok(()) => owned.source.statistics_valid = true,
                Err(source) => self.cleanup.push(failure(Phase::Statistics, source)),
            }
        }
    }
}

impl<C: Session> Session for Group<C> {
    fn metadata(&self) -> &Metadata {
        self.sources
            .first()
            .map_or(&UNARMED, |owned| &owned.source.metadata)
    }

    fn source_count(&self) -> usize {
        self.sources.len()
    }

    fn source_metadata(&self, source: usize) -> Option<&Metadata> {
        self.sources.get(source).map(|owned| &owned.source.metadata)
    }

    /// Waits for every source in order; all must be ready by the caller's
    /// deadline.
    fn wait_ready(&mut self, caller: &Deadline) -> Result<(), Error> {
        if !self.armed || self.closed || self.ready {
            return Err(self.fail(Error::CaptureGroupState));
        }
        if let Err(error) = check_cancelled(caller) {
            return Err(self.fail(error));
        }
        let Some(deadline) = wait_end(caller) else {
            return Err(self.fail(invalid("readiness timeout must be finite and positive")));
        };
        for index in 0..self.sources.len() {
            if let Err(error) = check_cancelled(caller) {
                return Err(self.fail(error));
            }
            if crate::deadline::remaining_before(deadline).is_none() {
                let failure = self.failure(
                    index,
                    Phase::Ready,
                    Error::CaptureReadiness {
                        message: "shared capture readiness deadline expired".to_owned(),
                    },
                );
                return Err(self.fail(failure));
            }
            if let Err(source) = self.sources[index].capture.wait_ready(caller) {
                let failure = self.failure(index, Phase::Ready, source);
                return Err(self.fail(failure));
            }
            if Instant::now() > deadline {
                let failure = self.failure(
                    index,
                    Phase::Ready,
                    Error::CaptureReadiness {
                        message: "provider exceeded shared readiness timeout".to_owned(),
                    },
                );
                return Err(self.fail(failure));
            }
            self.sources[index].source.ready = true;
        }
        if let Err(error) = check_cancelled(caller) {
            return Err(self.fail(error));
        }
        self.ready = true;
        Ok(())
    }

    /// Check all sources without waiting before taking one short blocking wait.
    /// Rotation after every returned record prevents a busy interface starving
    /// the others. An empty individual source never ends the group operation.
    ///
    /// A spent `deadline` polls every source once without waiting.
    fn next_captured_frame(&mut self, caller: &Deadline) -> Result<Option<Captured>, Error> {
        if !self.ready || self.closed {
            return Err(self.fail(Error::CaptureGroupState));
        }
        let deadline = match caller.remaining() {
            Ok(remaining) if remaining > super::MAX_TIMEOUT => {
                return Err(self.fail(invalid("capture wait exceeds its finite range")));
            }
            _ => wait_end(caller),
        };
        // Sources are first polled without waiting.
        let immediate = Deadline::new(Duration::ZERO);
        loop {
            if let Err(error) = check_cancelled(caller) {
                return Err(self.fail(error));
            }
            for _ in 0..self.sources.len() {
                let index = self.cursor;
                self.cursor = (self.cursor + 1) % self.sources.len();
                if let Some(captured) = self.poll(index, &immediate, caller)? {
                    return Ok(Some(captured));
                }
            }
            let Some(remaining) = deadline.and_then(crate::deadline::remaining_before) else {
                return Ok(None);
            };
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % self.sources.len();
            let wait = remaining.min(POLL_SLICE);
            let slice = Deadline::new(wait).with_cancellation(caller.cancellation().cloned());
            let started = Instant::now();
            if let Some(captured) = self.poll(index, &slice, caller)? {
                return Ok(Some(captured));
            }
            // Test/injected providers may return early. Keep an empty source
            // from making the shared live wait a busy loop.
            if let Some(pause) = wait.checked_sub(started.elapsed()) {
                std::thread::sleep(pause.min(Duration::from_millis(1)));
            }
        }
    }

    /// Shuts down every source not yet shut down, then reports every cleanup
    /// failure so far, including those from an earlier failed operation.
    /// Repeated calls report the same outcome.
    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_all();
        let mut failures = self.cleanup.iter().cloned();
        match failures.next() {
            None => Ok(()),
            Some(first) if self.cleanup.len() == 1 => Err(first),
            Some(first) => Err(Error::CaptureCleanup {
                first: Box::new(first),
                remaining: failures.collect(),
            }),
        }
    }

    /// Sums every source's counters, saturating each one.
    fn statistics(&self) -> Statistics {
        self.snapshot()
            .iter()
            .fold(Statistics::default(), |total, source| {
                let value = source.statistics;
                Statistics {
                    received_frames: total.received_frames.saturating_add(value.received_frames),
                    received_bytes: total.received_bytes.saturating_add(value.received_bytes),
                    dropped_frames: total.dropped_frames.saturating_add(value.dropped_frames),
                    dropped_bytes: total.dropped_bytes.saturating_add(value.dropped_bytes),
                    overflow_events: total.overflow_events.saturating_add(value.overflow_events),
                    receiver_dropped_frames: total
                        .receiver_dropped_frames
                        .saturating_add(value.receiver_dropped_frames),
                }
            })
    }
}

fn check_cancelled(deadline: &Deadline) -> Result<(), Error> {
    deadline.check_cancelled().map_err(Error::from)
}

/// The instant a group wait ends, or `None` once the caller's deadline is
/// spent or its remainder exceeds the public maximum.
fn wait_end(deadline: &Deadline) -> Option<Instant> {
    let remaining = deadline
        .remaining()
        .ok()
        .filter(|remaining| !remaining.is_zero() && *remaining <= super::MAX_TIMEOUT)?;
    Instant::now().checked_add(remaining)
}

impl<C: Session> Drop for Group<C> {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}
