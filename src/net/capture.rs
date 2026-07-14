// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Error;
use super::route::PlannedRoute;
use crate::capture::{DEFAULT_SIZE_LIMIT, Frame as CaptureFrame};

/// Aggregate backend capture-queue capacity used by default.
pub(crate) const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub(crate) const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Whether delivered capture evidence is known to include every observed
/// frame within the configured capture scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Incomplete,
}

/// Backend capture counters. Received counters include frames accepted by the
/// owned capture session. Dropped counters describe frames/bytes lost before
/// delivery; receiver drops are the subset reported by the native capture
/// source, and overflow events count distinct bounded-queue observations.
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
    /// Validates counter arithmetic and required frame/byte relationships.
    pub fn validate(self) -> Result<Self, Error> {
        self.received_frames
            .checked_add(self.dropped_frames)
            .ok_or_else(|| Error::InvalidCaptureStatistics {
                message: "received and dropped frame counters overflow u64".to_owned(),
            })?;
        self.received_bytes
            .checked_add(self.dropped_bytes)
            .ok_or_else(|| Error::InvalidCaptureStatistics {
                message: "received and dropped byte counters overflow u64".to_owned(),
            })?;
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

    /// Returns the evidence-completeness state derived from all public loss
    /// counters. Callers should not infer completeness from diagnostics.
    pub fn evidence_completeness(self) -> Completeness {
        if self.has_loss() {
            Completeness::Incomplete
        } else {
            Completeness::Complete
        }
    }

    /// Converts incomplete evidence into its typed queue-loss or receiver-loss
    /// error. Complete statistics return `None`.
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
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CaptureFrame>, Error>;
    /// Returns the frame with a monotonic ingress marker. Implementations that
    /// record ingress when the capture backend receives the frame should
    /// override this method and return [`Captured::new`]. The compatibility
    /// fallback deliberately leaves ingress time unavailable, which makes the
    /// frame ineligible for freshness correlation and latency measurement.
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        self.next_frame(timeout)
            .map(|frame| frame.map(Captured::without_ingress_time))
    }
    /// Stop the receiver and join all capture work before returning. An error
    /// means the implementation could not confirm complete cleanup.
    fn shutdown(&mut self) -> Result<(), Error>;
    /// Returns cumulative backend counters, including queue loss that was not
    /// otherwise observable through delivered frames.
    fn statistics(&self) -> Statistics;
}

/// Capture evidence paired with an optional monotonic receive marker. Wall-clock
/// packet time remains in [`CaptureFrame::timestamp`] for output; freshness and
/// latency use `received_at` so clock precision and adjustment cannot reorder
/// evidence.
#[derive(Clone, Debug)]
pub struct Captured {
    pub frame: CaptureFrame,
    /// Monotonic time recorded at capture ingress. `None` means the provider
    /// cannot prove when the frame entered its capture path.
    pub received_at: Option<Instant>,
}

impl Captured {
    pub fn new(frame: CaptureFrame, received_at: Instant) -> Self {
        Self {
            frame,
            received_at: Some(received_at),
        }
    }

    /// Retains a frame from a provider that cannot report capture ingress time.
    /// Such a frame is evidence, but cannot satisfy freshness correlation.
    pub fn without_ingress_time(frame: CaptureFrame) -> Self {
        Self {
            frame,
            received_at: None,
        }
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
    /// Validates non-zero limits, byte/snap consistency, and worst-case frame
    /// accounting before a backend allocates or starts capture.
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
        self.max_frames
            .checked_mul(self.snap_length)
            .ok_or(Error::InvalidCaptureQueueLimit {
                field: "max_frames * snap_length",
                value: self.max_frames,
                reason: "worst-case queue byte accounting overflows usize",
            })?;
        Ok(self)
    }
}

pub(crate) fn validate_timeout(timeout: Duration) -> Result<(), Error> {
    if timeout > MAX_TIMEOUT {
        return Err(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        });
    }
    Instant::now()
        .checked_add(timeout)
        .map(|_| ())
        .ok_or(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        })
}

/// Starts an owned capture stream using platform-neutral route and limit data.
pub trait Provider: Send + Sync {
    type Capture: Session;

    fn arm_capture(&self, route: &PlannedRoute, limits: Limits) -> Result<Self::Capture, Error>;
}

/// Owned native capture session. The native handle and capture worker remain
/// private behind this platform-neutral session wrapper.
pub struct SystemSession {
    inner: Box<dyn Session>,
}

impl SystemSession {
    pub(crate) fn new(inner: Box<dyn Session>) -> Self {
        Self { inner }
    }
}

impl Session for SystemSession {
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        self.inner.wait_ready(timeout)
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CaptureFrame>, Error> {
        validate_timeout(timeout)?;
        self.inner.next_frame(timeout)
    }

    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        validate_timeout(timeout)?;
        self.inner.next_captured_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }

    fn statistics(&self) -> Statistics {
        self.inner.statistics()
    }
}

/// Native capture provider selected for the current target and the explicit
/// `native-layer2` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, route: &PlannedRoute, limits: Limits) -> Result<Self::Capture, Error> {
        super::platform::system_capture(route, limits).map(SystemSession::new)
    }
}

pub(crate) use self::{
    Captured as CapturedFrame, Limits as CaptureQueueLimits,
    OverflowPolicy as CaptureOverflowPolicy, Provider as CaptureProvider,
    Session as CaptureSession, Statistics as CaptureStatistics,
    SystemProvider as SystemCaptureProvider,
};
#[cfg(all(
    test,
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) use Completeness as CaptureEvidenceCompleteness;

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::capture::LinkType;
    use crate::error::Classified;

    struct FrameOnlyCapture(Option<CaptureFrame>);

    impl Session for FrameOnlyCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
            Ok(())
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CaptureFrame>, Error> {
            Ok(self.0.take())
        }

        fn shutdown(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    #[test]
    fn capture_timeout_is_bounded_before_a_backend_wait() {
        assert!(validate_timeout(MAX_TIMEOUT).is_ok());
        let error = validate_timeout(Duration::MAX).unwrap_err();
        assert!(matches!(
            &error,
            Error::InvalidCaptureTimeout {
                maximum: MAX_TIMEOUT,
                ..
            }
        ));
        assert_eq!(error.classification().code, "cli.capture_timeout");
    }

    #[test]
    fn frame_only_capture_fallback_has_no_fabricated_ingress_time() {
        let frame = CaptureFrame::new(
            std::time::SystemTime::UNIX_EPOCH,
            LinkType::RAW,
            Bytes::from_static(&[1]),
        )
        .unwrap();
        let mut capture = FrameOnlyCapture(Some(frame));

        let captured = capture
            .next_captured_frame(Duration::ZERO)
            .unwrap()
            .unwrap();

        assert!(captured.received_at.is_none());
    }

    #[test]
    fn capture_completeness_and_loss_source_are_typed() {
        let receiver_loss = Statistics {
            dropped_frames: 2,
            receiver_dropped_frames: 2,
            ..Statistics::default()
        };
        assert_eq!(
            receiver_loss.validate().unwrap().evidence_completeness(),
            Completeness::Incomplete
        );
        assert!(matches!(
            receiver_loss.evidence_loss_error(),
            Some(Error::CaptureEvidenceLoss {
                receiver_dropped_frames: 2,
                ..
            })
        ));

        let invalid = Statistics {
            dropped_frames: 1,
            receiver_dropped_frames: 2,
            ..Statistics::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(Error::InvalidCaptureStatistics { .. })
        ));
    }
}
