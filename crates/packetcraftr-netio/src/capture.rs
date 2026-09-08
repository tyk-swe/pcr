// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::Error;
use super::interface::Id as InterfaceId;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::frame::{Frame as CaptureFrame, LinkType};

/// Aggregate backend capture-queue frame ceiling; also the value
/// [`Limits::default`] uses.
pub const MAX_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte ceiling; also the value
/// [`Limits::default`] uses.
pub const MAX_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
/// Largest per-frame snapshot a capture session will retain (16 MiB), matching
/// the default captured-frame size limit in `packetcraftr-core`; also the value
/// [`Limits::default`] uses.
pub const MAX_SNAP_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Capture counters for accepted frames and pre-delivery loss. Native receiver
/// drops are a subset; overflow events are bounded-queue observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Statistics {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(skip_serializing_if = "is_zero")]
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
    pub fn validate(&self) -> Result<(), Error> {
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
        Ok(())
    }

    /// Returns the typed loss error these counters describe, or `None` when the
    /// backend reported no drop and no queue overflow.
    pub fn evidence_loss_error(self) -> Option<Error> {
        if self.overflow_events != 0 {
            Some(Error::CaptureQueueOverflow {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                overflow_events: self.overflow_events,
            })
        } else if self.dropped_frames != 0
            || self.dropped_bytes != 0
            || self.receiver_dropped_frames != 0
        {
            Some(Error::CaptureEvidenceLoss {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                receiver_dropped_frames: self.receiver_dropped_frames,
            })
        } else {
            None
        }
    }
}

/// One owned live-capture session.
///
/// The lifecycle is fixed: a [`Provider`] returns an armed session,
/// [`Session::wait_ready`] is the barrier that must pass before any exchange
/// frame is transmitted, [`Session::next_captured_frame`] then delivers records
/// until the caller stops, and [`Session::shutdown`] joins the backend exactly
/// once. [`Session::statistics`] is only final after a successful shutdown.
pub trait Session: Send {
    /// Returns the backend-confirmed properties fixed when the session was activated.
    fn metadata(&self) -> &Metadata;
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error>;
    /// Waits up to `timeout` for the next record.
    ///
    /// `Ok(None)` means only "no record within this wait": the queue was empty,
    /// the timeout expired, or the backend stopped delivering. It is never
    /// evidence that nothing was captured, and it never ends the session — only
    /// [`Session::shutdown`] does. Loss is reported through
    /// [`Session::statistics`], not here.
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

/// Capture adapter that polls cooperatively for user cancellation. Provider
/// readiness and shutdown retain their original bounded lifecycle contracts.
/// A provider must honor each requested wait; arbitrary blocked provider code
/// cannot be preempted by this adapter.
pub struct Cancellable<C> {
    inner: C,
    cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl<C: Session> Cancellable<C> {
    pub fn new(inner: C, cancellation: Option<packetcraftr_core::budget::Cancellation>) -> Self {
        Self {
            inner,
            cancellation,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}

impl<C: Session> Session for Cancellable<C> {
    fn metadata(&self) -> &Metadata {
        self.inner.metadata()
    }
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        self.check()?;
        self.inner.wait_ready(timeout)?;
        self.check()
    }
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        let start = Instant::now();
        // Validate the original request before slicing it into polls: otherwise
        // cancellation would accidentally admit waits beyond the provider contract.
        if timeout > MAX_TIMEOUT || start.checked_add(timeout).is_none() {
            return Err(Error::InvalidCaptureTimeout {
                timeout,
                maximum: MAX_TIMEOUT,
            });
        }
        if self.cancellation.is_none() {
            return self.inner.next_captured_frame(timeout);
        }
        loop {
            self.check()?;
            let remaining = timeout.saturating_sub(start.elapsed());
            let frame = self
                .inner
                .next_captured_frame(remaining.min(Cancellation::POLL_INTERVAL))?;
            self.check()?;
            if frame.is_some() || start.elapsed() >= timeout {
                return Ok(frame);
            }
        }
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
    fn statistics(&self) -> Statistics {
        self.inner.statistics()
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

/// Opaque identity assigned exactly once when a record enters capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordIdentity(u64);

static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(1);

/// Capture evidence with an optional monotonic ingress marker. Wall-clock time is
/// output-only; freshness and latency use `received_at` to avoid reordering.
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

impl OverflowPolicy {
    /// The one spelling this policy is named by, in help text, in the
    /// `--overflow-policy` values a caller passes, and in the diagnostics that
    /// report which policy was in force.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::DropNewest => "drop-newest",
            Self::DropOldest => "drop-oldest",
        }
    }
}

impl fmt::Display for OverflowPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
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
            max_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_bytes: MAX_CAPTURE_QUEUE_BYTES,
            snap_length: MAX_SNAP_LENGTH,
            overflow_policy: OverflowPolicy::Fail,
        }
    }
}

impl Limits {
    /// Validates bounded nonzero limits and byte/snap consistency before capture.
    pub fn validate(&self) -> Result<(), Error> {
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
            ("max_frames", self.max_frames, MAX_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, MAX_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, MAX_SNAP_LENGTH),
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
        Ok(())
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

impl<S, C> Provider for crate::PacketIo<S, C>
where
    S: Send + Sync,
    C: Provider,
{
    type Capture = C::Capture;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error> {
        self.capture.arm_capture(request)
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use packetcraftr_core::budget::Cancellation;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Capture {
        metadata: Metadata,
        signal: Cancellation,
        stopped: Arc<AtomicBool>,
    }
    impl Session for Capture {
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }
        fn wait_ready(&mut self, _: Duration) -> Result<(), Error> {
            Ok(())
        }
        fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
            assert!(timeout <= Duration::from_millis(25));
            self.signal.cancel();
            Ok(None)
        }
        fn shutdown(&mut self) -> Result<(), Error> {
            self.stopped.store(true, Ordering::Release);
            Ok(())
        }
        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }
    #[test]
    fn cancellation_during_capture_wait_still_allows_explicit_shutdown() {
        let signal = Cancellation::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let capture = Capture {
            metadata: Metadata {
                interface: InterfaceId {
                    name: "fixture".to_owned(),
                    index: 1,
                },
                link_type: LinkType::IPV4,
                snap_length: 128,
            },
            signal: signal.clone(),
            stopped: stopped.clone(),
        };
        let mut capture = Cancellable::new(capture, Some(signal));
        capture.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            capture.next_captured_frame(Duration::MAX),
            Err(Error::InvalidCaptureTimeout { .. })
        ));
        assert!(matches!(
            capture.next_captured_frame(Duration::from_secs(60)),
            Err(Error::Cancelled(_))
        ));
        capture.shutdown().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }
}
