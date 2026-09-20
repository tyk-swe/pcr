// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded ownership, readiness, and fair delivery across selected interfaces.
//! Queue limits are partitioned across sources; each session keeps its native
//! metadata and records. Workflow/file layers choose capture-global output IDs.

use super::{Captured, Limits, Metadata, NativeSettings, Provider, Session, Statistics};
use crate::interface::Id;
use packetcraftr_core::{
    budget::Cancellation,
    error::{Classification, Classified, Kind},
};
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};
pub const MAX_SOURCES: usize = 16;
const POLL_SLICE: Duration = Duration::from_millis(5);

#[derive(Clone, Debug)]
pub struct Request {
    pub interfaces: Vec<Id>,
    pub limits: Limits,
    pub filter: Option<String>,
    pub promiscuous: bool,
    /// Optional native-driver settings applied to every source; each session
    /// reports its own realized values.
    pub native: NativeSettings,
}
impl Request {
    /// Validate the complete set before arming anything, then split both queue
    /// ceilings exactly, retaining a full snapshot's capacity in every source.
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 64 * 1024)
        {
            return Err(Error::new(Cause::Invalid("capture filter exceeds 64 KiB")));
        }
        let count = self.interfaces.len();
        if count == 0 || count > MAX_SOURCES {
            return Err(Error::new(Cause::Invalid(
                "select 1..=16 capture interfaces",
            )));
        }
        self.limits
            .validate()
            .and_then(|()| self.native.validate(&self.limits))
            .map_err(|source| Error::new(Cause::Configuration(source)))?;
        let mut identities = HashSet::new();
        for interface in &self.interfaces {
            if interface.name.len() > 4096 || !identities.insert(interface.index) {
                return Err(Error::new(Cause::Invalid(
                    "interface identities must be distinct and bounded",
                )));
            }
        }
        if self.limits.max_frames < count || self.limits.max_bytes / count < self.limits.snap_length
        {
            return Err(Error::new(Cause::Invalid(
                "shared queues must hold at least one full snapshot per interface",
            )));
        }
        Ok(())
    }
    pub fn partition(&self) -> Result<Vec<super::Request>, Error> {
        self.validate()?;
        let count = self.interfaces.len();
        Ok(self
            .interfaces
            .iter()
            .enumerate()
            .map(|(index, interface)| super::Request {
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
            .collect())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Arm,
    Ready,
    Receive,
    Shutdown,
    Statistics,
}
#[derive(Debug, thiserror::Error)]
#[error("capture source {index} ({}) during {phase:?}: {source}",.interface.name)]
#[non_exhaustive]
pub struct Failure {
    pub index: usize,
    pub interface: Id,
    pub phase: Phase,
    #[source]
    pub source: crate::Error,
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Cause {
    #[error("invalid capture group: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Configuration(crate::Error),
    #[error(transparent)]
    Provider(#[from] Failure),
    #[error("capture source {index} broke its provider contract: {message}")]
    Contract { index: usize, message: &'static str },
    #[error("capture group is not ready or has been shut down")]
    State,
}
impl Classified for Cause {
    fn classification(&self) -> Classification {
        match self {
            Self::Configuration(source) => source.classification(),
            Self::Provider(failure) => failure.source.classification(),
            Self::Invalid(_) => Classification::new("cli.capture_group", Kind::Cli, None),
            Self::Contract { .. } | Self::State => {
                Classification::new("internal.capture_group", Kind::Internal, None)
            }
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub struct Error {
    #[source]
    pub cause: Box<Cause>,
    pub cleanup: Vec<Failure>,
    pub sources: Vec<Source>,
}
impl Error {
    fn new(cause: Cause) -> Self {
        Self {
            cause: Box::new(cause),
            cleanup: Vec::new(),
            sources: Vec::new(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)?;
        for failure in &self.cleanup {
            write!(f, "; cleanup: {failure}")?;
        }
        Ok(())
    }
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        self.cause.classification()
    }
    fn causes(&self) -> Vec<String> {
        let mut causes = packetcraftr_core::error::source_chain(self);
        causes.extend(self.cleanup.iter().map(ToString::to_string));
        causes
    }
}
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
#[derive(Debug)]
pub struct Record {
    pub source: usize,
    pub captured: Captured,
}
struct Owned<C: Session> {
    capture: C,
    source: Source,
    shutdown_attempted: bool,
}
/// Every admitted session is shut down exactly once, including after partial
/// arming/readiness failures. Drop attempts remaining cleanup but cannot report
/// errors; callers should explicitly call `shutdown`.
pub struct Group<C: Session> {
    sources: Vec<Owned<C>>,
    cursor: usize,
    ready: bool,
    closed: bool,
    cancellation: Option<Cancellation>,
}
impl<C: Session> Group<C> {
    pub fn arm<P: Provider<Capture = C>>(
        provider: &P,
        request: &Request,
        cancellation: Option<Cancellation>,
    ) -> Result<Self, Error> {
        let requests = request.partition()?;
        let mut group = Self {
            sources: Vec::with_capacity(requests.len()),
            cursor: 0,
            ready: false,
            closed: false,
            cancellation,
        };
        for (index, request) in requests.iter().enumerate() {
            if let Err(cause) = group.check_cancelled() {
                return Err(group.fail(cause));
            }
            let capture = match provider.arm_capture(request) {
                Ok(capture) => capture,
                Err(source) => {
                    return Err(group.fail(Cause::Provider(Failure {
                        index,
                        interface: request.interface.clone(),
                        phase: Phase::Arm,
                        source,
                    })));
                }
            };
            let metadata = capture.metadata();
            let native = &metadata.native;
            let valid = metadata.interface == request.interface
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
            group.sources.push(Owned {
                capture,
                source: Source {
                    index,
                    metadata,
                    limits: request.limits,
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
                return Err(group.fail(Cause::Contract {
                    index,
                    message: "activation metadata disagrees with the request",
                }));
            }
        }
        Ok(group)
    }
    pub fn sources(&self) -> impl ExactSizeIterator<Item = &Source> {
        self.sources.iter().map(|source| &source.source)
    }
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
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        if self.closed || self.ready {
            return Err(self.fail(Cause::State));
        }
        let deadline = match Instant::now().checked_add(timeout) {
            Some(deadline) if !timeout.is_zero() && timeout <= super::MAX_TIMEOUT => deadline,
            _ => {
                return Err(self.fail(Cause::Invalid(
                    "readiness timeout must be finite and positive",
                )));
            }
        };
        for index in 0..self.sources.len() {
            if let Err(cause) = self.check_cancelled() {
                return Err(self.fail(cause));
            }
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
            else {
                return Err(self.fail(Cause::Provider(self.failure(
                    index,
                    Phase::Ready,
                    crate::Error::CaptureReadiness {
                        message: "shared capture readiness deadline expired".to_owned(),
                    },
                ))));
            };
            if let Err(source) = self.sources[index].capture.wait_ready(remaining) {
                return Err(self.fail(Cause::Provider(self.failure(index, Phase::Ready, source))));
            }
            if Instant::now() > deadline {
                return Err(self.fail(Cause::Provider(self.failure(
                    index,
                    Phase::Ready,
                    crate::Error::CaptureReadiness {
                        message: "provider exceeded shared readiness timeout".to_owned(),
                    },
                ))));
            }
            self.sources[index].source.ready = true;
        }
        if let Err(cause) = self.check_cancelled() {
            return Err(self.fail(cause));
        }
        self.ready = true;
        Ok(())
    }
    /// Check all sources without waiting before taking one short blocking wait.
    /// Rotation after every returned record prevents a busy interface starving
    /// the others. An empty individual source never ends the group operation.
    pub fn next_record(&mut self, timeout: Duration) -> Result<Option<Record>, Error> {
        if !self.ready || self.closed {
            return Err(self.fail(Cause::State));
        }
        let deadline = match Instant::now().checked_add(timeout) {
            Some(deadline) if timeout <= super::MAX_TIMEOUT => deadline,
            _ => return Err(self.fail(Cause::Invalid("capture wait exceeds its finite range"))),
        };
        loop {
            if let Err(cause) = self.check_cancelled() {
                return Err(self.fail(cause));
            }
            for _ in 0..self.sources.len() {
                let index = self.cursor;
                self.cursor = (self.cursor + 1) % self.sources.len();
                if let Some(record) = self.poll(index, Duration::ZERO)? {
                    return Ok(Some(record));
                }
            }
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
            else {
                return Ok(None);
            };
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % self.sources.len();
            let wait = remaining.min(POLL_SLICE);
            let started = Instant::now();
            if let Some(record) = self.poll(index, wait)? {
                return Ok(Some(record));
            }
            // Test/injected providers may return early. Keep an empty source
            // from making the shared live wait a busy loop.
            if let Some(pause) = wait.checked_sub(started.elapsed()) {
                std::thread::sleep(pause.min(Duration::from_millis(1)));
            }
        }
    }
    fn poll(&mut self, index: usize, timeout: Duration) -> Result<Option<Record>, Error> {
        let captured = match self.sources[index].capture.next_captured_frame(timeout) {
            Ok(Some(captured)) => captured,
            Ok(None) => return Ok(None),
            Err(source) => {
                return Err(self.fail(Cause::Provider(self.failure(
                    index,
                    Phase::Receive,
                    source,
                ))));
            }
        };
        if let Err(cause) = self.check_cancelled() {
            return Err(self.fail(cause));
        }
        let source = &mut self.sources[index].source;
        if captured.frame.link_type != source.metadata.link_type
            || captured.frame.bytes().len() > source.metadata.snap_length
            || captured
                .frame
                .interface
                .is_some_and(|interface| interface != source.metadata.interface.index)
        {
            return Err(self.fail(Cause::Contract {
                index,
                message: "captured frame disagrees with activated source metadata",
            }));
        }
        let (Some(frames), Some(bytes)) = (
            source.delivered_frames.checked_add(1),
            source
                .delivered_bytes
                .checked_add(u64::from(captured.frame.captured_length())),
        ) else {
            return Err(self.fail(Cause::Contract {
                index,
                message: "delivery counters overflowed",
            }));
        };
        source.delivered_frames = frames;
        source.delivered_bytes = bytes;
        Ok(Some(Record {
            source: index,
            captured,
        }))
    }
    /// Whether shutdown has already been attempted for the group's sessions.
    pub fn shutdown_attempted(&self) -> bool {
        self.closed
    }
    pub fn shutdown(&mut self) -> Result<Vec<Source>, Error> {
        if self.closed
            && self
                .sources
                .iter()
                .any(|owned| !owned.source.shutdown_confirmed || !owned.source.statistics_valid)
        {
            return Err(Error {
                cause: Box::new(Cause::State),
                cleanup: Vec::new(),
                sources: self.snapshot(),
            });
        }
        let failures = self.shutdown_all();
        let sources = self.snapshot();
        let mut failures = failures.into_iter();
        if let Some(first) = failures.next() {
            return Err(Error {
                cause: Box::new(Cause::Provider(first)),
                cleanup: failures.collect(),
                sources,
            });
        }
        Ok(sources)
    }
    fn failure(&self, index: usize, phase: Phase, source: crate::Error) -> Failure {
        Failure {
            index,
            interface: self.sources[index].source.metadata.interface.clone(),
            phase,
            source,
        }
    }
    fn check_cancelled(&self) -> Result<(), Cause> {
        self.cancellation.as_ref().map_or(Ok(()), |signal| {
            signal
                .check()
                .map_err(crate::Error::from)
                .map_err(Cause::Configuration)
        })
    }
    fn fail(&mut self, cause: Cause) -> Error {
        let cleanup = self.shutdown_all();
        Error {
            cause: Box::new(cause),
            cleanup,
            sources: self.snapshot(),
        }
    }
    fn shutdown_all(&mut self) -> Vec<Failure> {
        self.closed = true;
        self.ready = false;
        let mut failures = Vec::new();
        for owned in &mut self.sources {
            if owned.shutdown_attempted {
                continue;
            }
            owned.shutdown_attempted = true;
            match owned.capture.shutdown() {
                Ok(()) => owned.source.shutdown_confirmed = true,
                Err(source) => failures.push(Failure {
                    index: owned.source.index,
                    interface: owned.source.metadata.interface.clone(),
                    phase: Phase::Shutdown,
                    source,
                }),
            }
            owned.source.statistics = owned.capture.statistics();
            match owned.source.statistics.validate() {
                Ok(()) => owned.source.statistics_valid = true,
                Err(source) => failures.push(Failure {
                    index: owned.source.index,
                    interface: owned.source.metadata.interface.clone(),
                    phase: Phase::Statistics,
                    source,
                }),
            }
        }
        failures
    }
}
impl<C: Session> Drop for Group<C> {
    fn drop(&mut self) {
        let _ = self.shutdown_all();
    }
}
