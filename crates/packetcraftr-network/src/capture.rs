// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Error;
use super::route::PlannedRoute;
use packetcraftr_packet::frame::{DEFAULT_SIZE_LIMIT, Frame as CaptureFrame};

pub(crate) use self::{
    Captured as CapturedFrame, Limits as CaptureQueueLimits,
    OverflowPolicy as CaptureOverflowPolicy, Provider as CaptureProvider,
    Session as CaptureSession, SystemProvider as SystemCaptureProvider,
};
/// Aggregate backend capture-queue capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Capture counters for accepted frames and pre-delivery loss. Native receiver
/// drops are a subset; overflow events are bounded-queue observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statistics {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Statistics {
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
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error>;
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error>;
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
    /// Returns cumulative counters, including undelivered queue loss.
    fn statistics(&self) -> Statistics;
}

impl<T: Session + ?Sized> Session for Box<T> {
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

/// Capture evidence with an optional monotonic ingress marker. Wall-clock time is
/// output-only; freshness and latency use `received_at` to avoid reordering.
#[derive(Clone, Debug)]
pub struct Captured {
    pub frame: CaptureFrame,
    /// Monotonic ingress time; `None` cannot prove freshness.
    pub received_at: Option<Instant>,
}

impl Captured {
    pub fn new(frame: CaptureFrame, received_at: Instant) -> Self {
        Self::with_ingress_time(frame, Some(received_at))
    }

    /// Retains an optional provider-supplied monotonic ingress marker.
    pub fn with_ingress_time(frame: CaptureFrame, received_at: Option<Instant>) -> Self {
        Self { frame, received_at }
    }

    /// Evidence without an ingress marker cannot satisfy freshness correlation.
    pub fn without_ingress_time(frame: CaptureFrame) -> Self {
        Self::with_ingress_time(frame, None)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Starts an owned capture stream using platform-neutral route and limit data.
pub trait Provider: Send + Sync {
    type Capture: Session;

    fn arm_capture(&self, route: &PlannedRoute, limits: Limits) -> Result<Self::Capture, Error>;

    /// Starts capture with native BPF filtering; unsupported providers fail closed.
    fn arm_capture_with_filter(
        &self,
        _route: &PlannedRoute,
        _limits: Limits,
        _filter: &str,
    ) -> Result<Self::Capture, Error> {
        Err(Error::Unsupported {
            message: "this capture provider cannot install native capture filters".to_owned(),
        })
    }
}

/// Platform-native capture session with private handle and worker.
pub type SystemSession = Box<dyn Session>;

/// Target-selected native capture provider; requires `native-layer2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, route: &PlannedRoute, limits: Limits) -> Result<Self::Capture, Error> {
        super::platform::system_capture(route, limits)
    }

    fn arm_capture_with_filter(
        &self,
        route: &PlannedRoute,
        limits: Limits,
        filter: &str,
    ) -> Result<Self::Capture, Error> {
        super::platform::system_capture_with_filter(route, limits, filter)
    }
}
