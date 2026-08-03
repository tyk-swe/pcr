// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Error;
use super::route::PlannedRoute;
use packetcraftr_core::frame::{DEFAULT_SIZE_LIMIT, Frame as CaptureFrame};

#[doc(hidden)]
pub use self::{
    Captured as CapturedFrame, Limits as CaptureQueueLimits,
    OverflowPolicy as CaptureOverflowPolicy, Provider as CaptureProvider,
    Session as CaptureSession, Statistics as CaptureStatistics,
    SystemProvider as SystemCaptureProvider,
};
/// Aggregate backend capture-queue capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

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
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error>;
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
        Self::with_ingress_time(frame, Some(received_at))
    }

    /// Retains an optional provider-supplied monotonic ingress marker.
    pub fn with_ingress_time(frame: CaptureFrame, received_at: Option<Instant>) -> Self {
        Self { frame, received_at }
    }

    /// Retains a frame from a provider that cannot report capture ingress time.
    /// Such a frame is evidence, but cannot satisfy freshness correlation.
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
    /// Validates bounded non-zero limits and byte/snap consistency before a
    /// backend allocates or starts capture.
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

    /// Starts capture with a native libpcap/Npcap BPF filter. Providers that
    /// cannot install native filters fail closed instead of falling back to
    /// unfiltered capture.
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

    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
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

    fn arm_capture_with_filter(
        &self,
        route: &PlannedRoute,
        limits: Limits,
        filter: &str,
    ) -> Result<Self::Capture, Error> {
        super::platform::system_capture_with_filter(route, limits, filter).map(SystemSession::new)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::route::models::{LinkCapability, LinkMode};
    use crate::route::{
        DestinationScope, InterfaceId, PlannedRoute, RouteDecision, RouteSelectionReason,
    };
    use packetcraftr_core::frame::LinkType;

    #[derive(Debug)]
    struct TestCapture;

    impl Session for TestCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
            Ok(())
        }

        fn next_captured_frame(&mut self, _timeout: Duration) -> Result<Option<Captured>, Error> {
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    struct DefaultFilterProvider {
        ordinary_calls: Arc<AtomicUsize>,
    }

    impl Provider for DefaultFilterProvider {
        type Capture = TestCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            _limits: Limits,
        ) -> Result<Self::Capture, Error> {
            self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestCapture)
        }
    }

    struct FilterProvider {
        ordinary_calls: Arc<AtomicUsize>,
        filtered_calls: Arc<AtomicUsize>,
    }

    impl Provider for FilterProvider {
        type Capture = TestCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            _limits: Limits,
        ) -> Result<Self::Capture, Error> {
            self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestCapture)
        }

        fn arm_capture_with_filter(
            &self,
            _route: &PlannedRoute,
            _limits: Limits,
            filter: &str,
        ) -> Result<Self::Capture, Error> {
            assert_eq!(filter, "udp port 53");
            self.filtered_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestCapture)
        }
    }

    fn route() -> PlannedRoute {
        PlannedRoute {
            route: RouteDecision {
                interface: InterfaceId {
                    name: "test0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_address: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: RouteSelectionReason::InterfaceOnly,
                destination_scope: DestinationScope::Unspecified,
                mtu: 1_500,
                capability: LinkCapability::Layer2,
                link_type: LinkType(1),
            },
            mode: LinkMode::Layer2,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        }
    }

    #[test]
    fn capture_completeness_and_loss_source_are_typed() {
        let receiver_loss = Statistics {
            dropped_frames: 2,
            receiver_dropped_frames: 2,
            ..Statistics::default()
        };
        receiver_loss.validate().unwrap();
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

    #[test]
    fn native_filter_default_fails_closed_without_ordinary_capture_fallback() {
        let ordinary_calls = Arc::new(AtomicUsize::new(0));
        let provider = DefaultFilterProvider {
            ordinary_calls: Arc::clone(&ordinary_calls),
        };

        let error = provider
            .arm_capture_with_filter(&route(), Limits::default(), "udp port 53")
            .unwrap_err();
        assert!(matches!(error, Error::Unsupported { .. }));
        assert_eq!(ordinary_calls.load(Ordering::SeqCst), 0);

        provider.arm_capture(&route(), Limits::default()).unwrap();
        assert_eq!(ordinary_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tuple_preserves_ordinary_and_filtered_capture_delegation() {
        let ordinary_calls = Arc::new(AtomicUsize::new(0));
        let filtered_calls = Arc::new(AtomicUsize::new(0));
        let provider = FilterProvider {
            ordinary_calls: Arc::clone(&ordinary_calls),
            filtered_calls: Arc::clone(&filtered_calls),
        };
        let composite = ((), provider);

        composite.arm_capture(&route(), Limits::default()).unwrap();
        composite
            .arm_capture_with_filter(&route(), Limits::default(), "udp port 53")
            .unwrap();

        assert_eq!(ordinary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(filtered_calls.load(Ordering::SeqCst), 1);
    }
}
