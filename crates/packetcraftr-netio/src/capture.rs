// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::Error;
use super::interface::Id as InterfaceId;
use packetcraftr_core::frame::{DEFAULT_SIZE_LIMIT, Frame as CaptureFrame, LinkType};

pub(crate) use self::{
    Captured as CapturedFrame, Limits as CaptureQueueLimits,
    OverflowPolicy as CaptureOverflowPolicy, Provider as CaptureProvider,
    Request as CaptureRequest, Session as CaptureSession,
};
/// Aggregate backend capture-queue capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Capture counters for accepted frames and pre-delivery loss. Native receiver
/// drops are a subset; overflow events are bounded-queue observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    pub receiver_dropped_frames: u64,
}

impl Statistics {
    /// Returns the fieldwise sum, or `None` if any counter would overflow.
    pub fn checked_add(self, value: Self) -> Option<Self> {
        Some(Self {
            received_frames: self.received_frames.checked_add(value.received_frames)?,
            received_bytes: self.received_bytes.checked_add(value.received_bytes)?,
            dropped_frames: self.dropped_frames.checked_add(value.dropped_frames)?,
            dropped_bytes: self.dropped_bytes.checked_add(value.dropped_bytes)?,
            overflow_events: self.overflow_events.checked_add(value.overflow_events)?,
            receiver_dropped_frames: self
                .receiver_dropped_frames
                .checked_add(value.receiver_dropped_frames)?,
        })
    }

    /// Validates required frame/byte counter relationships.
    pub fn validate(self) -> Result<Self, Error> {
        if self.dropped_frames == 0 && self.dropped_bytes != 0 {
            return Err(Error::InvalidCaptureStatistics {
                message: "dropped bytes were reported without a dropped frame".to_owned(),
            });
        }
        if self.receiver_dropped_frames > self.dropped_frames {
            return Err(Error::InvalidCaptureStatistics {
                message: "receiver-dropped frames exceed total dropped frames".to_owned(),
            });
        }
        Ok(self)
    }

    /// Returns whether the backend reported any drop or queue overflow.
    pub fn has_loss(self) -> bool {
        self.dropped_frames != 0
            || self.dropped_bytes != 0
            || self.overflow_events != 0
            || self.receiver_dropped_frames != 0
    }

    /// Returns a typed loss error, or `None` for complete evidence.
    pub fn evidence_loss_error(self) -> Option<Error> {
        if !self.has_loss() {
            None
        } else if self.overflow_events != 0 {
            Some(Error::CaptureQueueOverflow {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                overflow_events: self.overflow_events,
            })
        } else {
            Some(Error::CaptureEvidenceLoss {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                receiver_dropped_frames: self.receiver_dropped_frames,
            })
        }
    }
}

pub trait Session: Send {
    /// Returns the backend-confirmed properties fixed when the session was activated.
    fn metadata(&self) -> &Metadata;
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error>;
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error>;
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
    /// Returns cumulative counters, including undelivered queue loss.
    fn statistics(&self) -> Statistics;
}

impl<T: Session + ?Sized> Session for Box<T> {
    fn metadata(&self) -> &Metadata {
        (**self).metadata()
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        (**self).wait_ready(timeout)
    }

    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        (**self).next_captured_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        (**self).shutdown()
    }

    fn statistics(&self) -> Statistics {
        (**self).statistics()
    }
}

/// Configuration for one single-interface capture session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub interface: InterfaceId,
    pub limits: Limits,
    /// Native filter that the provider must install before delivery or reject.
    pub filter: Option<String>,
    pub promiscuous: bool,
}

/// Backend-confirmed properties of an activated capture session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub interface: InterfaceId,
    pub link_type: LinkType,
    pub snap_length: usize,
}

/// Capture evidence with an optional monotonic ingress marker. Wall-clock time is
/// output-only; freshness and latency use `received_at` to avoid reordering.
/// Opaque identity assigned exactly once when a record enters capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordIdentity(u64);

static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct Captured {
    identity: RecordIdentity,
    pub frame: CaptureFrame,
    /// Monotonic ingress time; `None` cannot prove freshness.
    pub received_at: Option<Instant>,
}

impl Captured {
    pub fn new(frame: CaptureFrame, received_at: Instant) -> Self {
        Self::with_ingress_time(frame, Some(received_at))
    }

    /// Retains an optional provider-supplied monotonic ingress marker.
    ///
    /// # Panics
    ///
    /// Panics only if the process exhausts the non-reusable capture-record
    /// identity space.
    pub fn with_ingress_time(frame: CaptureFrame, received_at: Option<Instant>) -> Self {
        let identity = NEXT_RECORD_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("capture record identity space exhausted");
        Self {
            identity: RecordIdentity(identity),
            frame,
            received_at,
        }
    }

    /// Evidence without an ingress marker cannot satisfy freshness correlation.
    pub fn without_ingress_time(frame: CaptureFrame) -> Self {
        Self::with_ingress_time(frame, None)
    }

    pub fn identity(&self) -> RecordIdentity {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub snap_length: usize,
    pub overflow_policy: OverflowPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            snap_length: DEFAULT_SIZE_LIMIT,
            overflow_policy: OverflowPolicy::Fail,
        }
    }
}

impl Limits {
    /// Validates bounded nonzero limits and byte/snap consistency before capture.
    pub fn validate(self) -> Result<Self, Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("snap_length", self.snap_length),
        ] {
            if value == 0 {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "must be greater than zero",
                });
            }
        }
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, DEFAULT_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, DEFAULT_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, DEFAULT_SIZE_LIMIT),
        ] {
            if value > maximum {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "exceeds the stable configured maximum",
                });
            }
        }
        if self.snap_length > self.max_bytes {
            return Err(Error::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: self.snap_length,
                reason: "cannot exceed max_bytes",
            });
        }
        Ok(self)
    }
}

/// Starts an owned capture stream using platform-neutral interface data.
pub trait Provider: Send + Sync {
    type Capture: Session;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error>;
}

/// Platform-native capture session with private handle and worker.
pub type SystemSession = Box<dyn Session>;

/// Target-selected native capture provider; requires `native-layer2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error> {
        super::platform::system_capture(request)
    }
}
