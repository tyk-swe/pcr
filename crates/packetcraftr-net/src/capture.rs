// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Error;
use super::route::PlannedRoute;
use packetcraftr_capture::{DEFAULT_SIZE_LIMIT, Frame as CaptureFrame};

#[doc(hidden)]
pub use self::{
    Captured as CapturedFrame, Limits as CaptureQueueLimits, Options as CaptureOptions,
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

/// Everything one capture session is armed with.
///
/// Bounds live in [`Limits`]; this adds the backend behaviour a caller can
/// choose. Providers that cannot honor a non-default choice must reject it
/// rather than capture more traffic than was asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    /// Whether the backend places the interface in promiscuous mode.
    ///
    /// Promiscuous capture is the default here and in `tcpdump`; disabling it
    /// narrows capture to traffic the interface would have accepted anyway.
    pub promiscuous: Promiscuous,
    /// A libpcap-syntax filter applied by the capture backend, before frames
    /// reach this process at all.
    ///
    /// This is a different mechanism from a display filter: it decides what is
    /// captured, not what is shown, and it is expressed in the backend's own
    /// syntax rather than the reflective field vocabulary.
    pub filter: Option<String>,
}

/// Whether an armed capture asks the interface for all visible traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Promiscuous {
    #[default]
    Enabled,
    Disabled,
}

impl Promiscuous {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl Options {
    /// Arms with the default backend behaviour under explicit bounds.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            promiscuous: Promiscuous::Enabled,
            filter: None,
        }
    }

    pub fn validate(self) -> Result<Self, Error> {
        Ok(Self {
            limits: self.limits.validate()?,
            ..self
        })
    }

    /// Rejects every option a provider cannot honor.
    ///
    /// A provider that silently ignored these would capture more traffic than
    /// the caller asked for, so the shared fallback fails closed instead.
    pub fn require_backend_defaults(&self) -> Result<(), Error> {
        if !self.promiscuous.is_enabled() {
            return Err(Error::Unsupported {
                message: "this capture provider cannot disable promiscuous mode".to_owned(),
            });
        }
        if let Some(filter) = &self.filter {
            return Err(Error::InvalidCaptureFilter {
                filter: filter.clone(),
                message: "this capture provider cannot apply a kernel filter".to_owned(),
            });
        }
        Ok(())
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

    /// Starts a capture with the complete option set.
    ///
    /// The default accepts only the backend defaults and rejects everything
    /// else, so a provider written before an option existed fails closed
    /// instead of quietly capturing more traffic than was requested. Override
    /// this to honor the options a backend can actually apply.
    fn arm_capture_with(
        &self,
        route: &PlannedRoute,
        options: Options,
    ) -> Result<Self::Capture, Error> {
        options.require_backend_defaults()?;
        self.arm_capture(route, options.limits)
    }
}

/// Owned native capture session. The native handle and capture worker remain
/// private behind this platform-neutral session wrapper. Timeout policy is
/// enforced here before delegation; native backends also defend their direct
/// crate-internal entry points.
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
        validate_timeout(timeout)?;
        self.inner.wait_ready(timeout)
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
        self.arm_capture_with(route, Options::new(limits))
    }

    fn arm_capture_with(
        &self,
        route: &PlannedRoute,
        options: Options,
    ) -> Result<Self::Capture, Error> {
        super::platform::system_capture(route, options).map(SystemSession::new)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use packetcraftr_error::Classified;

    #[derive(Debug)]
    struct CountingCapture {
        calls: Arc<AtomicUsize>,
    }

    impl Session for CountingCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn next_captured_frame(&mut self, _timeout: Duration) -> Result<Option<Captured>, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    #[test]
    fn system_session_rejects_invalid_timeouts_before_delegation() {
        assert!(validate_timeout(MAX_TIMEOUT).is_ok());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut session = SystemSession::new(Box::new(CountingCapture {
            calls: Arc::clone(&calls),
        }));

        let errors = [
            session.wait_ready(Duration::MAX).unwrap_err(),
            session.next_captured_frame(Duration::MAX).unwrap_err(),
        ];
        for error in errors {
            assert!(matches!(
                &error,
                Error::InvalidCaptureTimeout {
                    maximum: MAX_TIMEOUT,
                    ..
                }
            ));
            assert_eq!(error.classification().code, "cli.capture_timeout");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct DefaultsOnlyProvider(Arc<AtomicUsize>);

    impl Provider for DefaultsOnlyProvider {
        type Capture = CountingCapture;

        fn arm_capture(
            &self,
            _route: &PlannedRoute,
            _limits: Limits,
        ) -> Result<Self::Capture, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(CountingCapture {
                calls: Arc::clone(&self.0),
            })
        }
    }

    fn observation_plan() -> PlannedRoute {
        PlannedRoute {
            route: crate::route::RouteDecision {
                interface: crate::route::InterfaceId {
                    name: "test0".to_owned(),
                    index: 7,
                },
                source_mac: None,
                selected_address: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: crate::route::RouteSelectionReason::InterfaceOnly,
                destination_scope: crate::route::DestinationScope::Link,
                mtu: 1500,
                capability: crate::link::Capability::Layer2,
                link_type: packetcraftr_capture::LinkType::ETHERNET,
            },
            mode: crate::link::Mode::Auto,
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
    fn a_provider_without_option_support_refuses_non_default_options() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = DefaultsOnlyProvider(Arc::clone(&calls));
        let plan = observation_plan();

        provider
            .arm_capture_with(&plan, Options::new(Limits::default()))
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Silently capturing promiscuously, or ignoring a kernel filter, would
        // give the caller more traffic than it asked for, so the fallback
        // refuses instead.
        let refused = provider
            .arm_capture_with(
                &plan,
                Options {
                    promiscuous: Promiscuous::Disabled,
                    ..Options::new(Limits::default())
                },
            )
            .unwrap_err();
        assert!(matches!(refused, Error::Unsupported { .. }));

        let refused = provider
            .arm_capture_with(
                &plan,
                Options {
                    filter: Some("udp port 53".to_owned()),
                    ..Options::new(Limits::default())
                },
            )
            .unwrap_err();
        assert!(matches!(
            refused,
            Error::InvalidCaptureFilter { ref filter, .. } if filter == "udp port 53"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn capture_options_validate_their_bounds_and_default_to_promiscuous() {
        assert_eq!(Options::default().promiscuous, Promiscuous::Enabled);
        assert_eq!(Options::default().filter, None);
        assert!(Promiscuous::Enabled.is_enabled());
        assert!(!Promiscuous::Disabled.is_enabled());

        let invalid = Options::new(Limits {
            max_frames: 0,
            ..Limits::default()
        });
        assert!(matches!(
            invalid.validate(),
            Err(Error::InvalidCaptureQueueLimit {
                field: "max_frames",
                ..
            })
        ));
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
}
