// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Captured, Limits, Metadata, NativeSettings, Provider, Realized, RealizedSettings, Request,
    Session, Stats,
};
use crate::{Error, interface::Id};
use packetcraftr_core::{budget::Deadline, frame::LinkType};
use source::Owned;
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

mod source;

/// Sources one group arms at once. One worker-pool slot stays free for the
/// persistent Linux netlink route worker and other pooled work; without it the
/// last source of a full group is refused while the other readers run.
pub const MAX_SOURCES: usize = crate::resources::WORKER_CAPACITY - 1;
/// Longest wait on one source before the group checks the others.
const POLL_SLICE: Duration = Duration::from_millis(5);
const MAX_INTERFACE_NAME_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct GroupRequest {
    pub interfaces: Vec<Id>,
    pub limits: Limits,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub native: NativeSettings,
}

impl GroupRequest {
    pub fn validate(&self) -> Result<(), Error> {
        super::validate_filter_length(self.filter.as_deref())?;
        let count = self.interfaces.len();
        if count == 0 || count > MAX_SOURCES {
            return Err(invalid("select 1..=15 capture interfaces"));
        }
        self.limits.validate()?;
        self.native.validate(&self.limits)?;
        let mut identities = HashSet::new();
        for interface in &self.interfaces {
            if interface.name.len() > MAX_INTERFACE_NAME_BYTES
                || !identities.insert(interface.index)
            {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Arm,
    Ready,
    Receive,
    Shutdown,
    Stats,
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Arm => "arming",
            Self::Ready => "readiness",
            Self::Receive => "receive",
            Self::Shutdown => "shutdown",
            Self::Stats => "statistics",
        })
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
    pub statistics: Stats,
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
}

/// Reported by [`Session::metadata`] for a group that admitted no source.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    New,
    Armed,
    Ready,
    Closed,
}

pub struct Group<C: Session> {
    requests: Vec<Request>,
    sources: Vec<Owned<C>>,
    cleanup: Vec<Error>,
    cursor: usize,
    lifecycle: Lifecycle,
}

impl<C: Session> Group<C> {
    pub fn new(request: &GroupRequest) -> Result<Self, Error> {
        request.validate()?;
        let requests = request.partition();
        Ok(Self {
            sources: Vec::with_capacity(requests.len()),
            requests,
            cleanup: Vec::new(),
            cursor: 0,
            lifecycle: Lifecycle::New,
        })
    }

    pub fn arm<P: Provider<Capture = C>>(
        &mut self,
        provider: &P,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        self.arm_sources(provider, deadline)
            .map_err(|error| self.fail(error))
    }

    fn arm_sources<P: Provider<Capture = C>>(
        &mut self,
        provider: &P,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        if self.lifecycle != Lifecycle::New {
            return Err(Error::CaptureGroupState);
        }
        self.lifecycle = Lifecycle::Armed;
        for index in 0..self.requests.len() {
            deadline.check_cancelled()?;
            let request = &self.requests[index];
            let capture =
                provider
                    .arm_capture(request, deadline)
                    .map_err(|source| Error::CaptureSource {
                        index,
                        interface: request.interface.clone(),
                        phase: Phase::Arm,
                        source: Box::new(source),
                    })?;
            let owned = Owned::new(index, request, capture);
            let valid = owned.source.metadata_valid;
            self.sources.push(owned);
            if !valid {
                return Err(Error::CaptureSourceContract {
                    index,
                    reason: "activation metadata disagrees with the request",
                });
            }
        }
        Ok(())
    }

    pub fn sources(&self) -> impl ExactSizeIterator<Item = &Source> {
        self.sources.iter().map(|source| &source.source)
    }

    pub fn snapshot(&self) -> Vec<Source> {
        self.sources.iter().map(Owned::snapshot).collect()
    }

    fn wait_sources_ready(&mut self, caller: &Deadline) -> Result<(), Error> {
        if self.lifecycle != Lifecycle::Armed {
            return Err(Error::CaptureGroupState);
        }
        let Some(deadline) = super::wait_end(caller)? else {
            return Err(Error::CaptureReadiness {
                message: "capture readiness deadline expired".to_owned(),
            });
        };
        for owned in &mut self.sources {
            owned.wait_ready(caller, deadline)?;
        }
        caller.check_cancelled()?;
        self.lifecycle = Lifecycle::Ready;
        Ok(())
    }

    /// Rotation after every returned record prevents a busy interface starving
    /// the others.
    fn receive_frame(&mut self, caller: &Deadline) -> Result<Option<Captured>, Error> {
        if self.lifecycle != Lifecycle::Ready {
            return Err(Error::CaptureGroupState);
        }
        let deadline = super::wait_end(caller)?;
        let immediate = Deadline::new(Duration::ZERO);
        loop {
            caller.check_cancelled()?;
            for _ in 0..self.sources.len() {
                let index = self.cursor;
                self.cursor = (self.cursor + 1) % self.sources.len();
                if let Some(captured) = self.sources[index].poll(&immediate, caller)? {
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
            if let Some(captured) = self.sources[index].poll(&slice, caller)? {
                return Ok(Some(captured));
            }
            // Test/injected providers may return early: keep the wait from busy-looping.
            if let Some(pause) = wait.checked_sub(started.elapsed()) {
                std::thread::sleep(pause.min(Duration::from_millis(1)));
            }
        }
    }

    fn fail(&mut self, error: Error) -> Error {
        self.shutdown_all();
        error
    }

    fn shutdown_all(&mut self) {
        self.lifecycle = Lifecycle::Closed;
        for owned in &mut self.sources {
            owned.shutdown(&mut self.cleanup);
        }
    }
}

impl<C: Session> Session for Group<C> {
    fn supports_ingress_time(&self) -> bool {
        !self.sources.is_empty() && self.sources.iter().all(Owned::supports_ingress_time)
    }
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

    fn wait_ready(&mut self, caller: &Deadline) -> Result<(), Error> {
        self.wait_sources_ready(caller)
            .map_err(|error| self.fail(error))
    }

    fn next_captured_frame(&mut self, caller: &Deadline) -> Result<Option<Captured>, Error> {
        self.receive_frame(caller).map_err(|error| self.fail(error))
    }

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

    fn stats(&self) -> Stats {
        self.snapshot()
            .iter()
            .fold(Stats::default(), |total, source| {
                let value = source.statistics;
                Stats {
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

impl<C: Session> Drop for Group<C> {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}
