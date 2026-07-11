// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral contracts implemented by native and test I/O providers.

use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{ClassifiedError, ErrorClassification, FailureKind};

use super::{
    CapturedFrame, InterfaceId, LinkCapability, LinkMode, LinkType, MacAddress, MaterializedRoute,
    PlannedRoute, DEFAULT_CAPTURE_SIZE_LIMIT,
};

/// Aggregate backend capture-queue capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_CAPTURE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// One address assigned to an interface, without any operating-system type in
/// the public provider boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// Portable interface state exposed by every platform adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceFlags {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

/// Platform-neutral interface description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub id: InterfaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<MacAddress>,
    pub addresses: Vec<InterfaceAddress>,
    pub flags: InterfaceFlags,
    /// Native interface MTU. Temporary portable enumeration adapters may not
    /// expose it and return `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: LinkCapability,
    pub link_type: LinkType,
}

/// Enumerates interfaces without exposing a native handle or wrapper type.
pub trait InterfaceProvider: Send + Sync {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError>;
}

/// Provider backed by the adapter selected for the current target and feature
/// set. Portable profiles return a typed capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemInterfaceProvider;

impl InterfaceProvider for SystemInterfaceProvider {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError> {
        super::platform::system_interfaces()
    }
}

/// A complete Layer 2 frame. Construction rejects a route selected for raw
/// Layer 3 transmission.
#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, LiveIoError> {
        require_link_mode(route, LinkMode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
        self.route
    }
}

/// A raw Layer 3 packet. Construction rejects a route selected for link-layer
/// transmission, preventing an Ethernet envelope from reaching a raw socket.
#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, LiveIoError> {
        require_link_mode(route, LinkMode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
        self.route
    }
}

/// Mode-tagged transmission input used by the high-level client.
#[derive(Clone, Copy, Debug)]
pub enum TransmissionFrame<'a> {
    Layer2(Layer2Frame<'a>),
    Layer3(Layer3Frame<'a>),
}

impl<'a> TransmissionFrame<'a> {
    /// Selects the typed provider boundary from the already-materialized route.
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, LiveIoError> {
        match route.plan.mode {
            LinkMode::Layer2 => Layer2Frame::try_new(bytes, route).map(Self::Layer2),
            LinkMode::Layer3 => Layer3Frame::try_new(bytes, route).map(Self::Layer3),
            LinkMode::Auto => Err(LiveIoError::UnresolvedLinkMode),
        }
    }

    pub fn bytes(self) -> &'a Bytes {
        match self {
            Self::Layer2(frame) => frame.bytes(),
            Self::Layer3(frame) => frame.bytes(),
        }
    }

    pub fn route(self) -> &'a MaterializedRoute {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }

    pub fn link_mode(self) -> LinkMode {
        match self {
            Self::Layer2(_) => LinkMode::Layer2,
            Self::Layer3(_) => LinkMode::Layer3,
        }
    }
}

fn require_link_mode(route: &MaterializedRoute, expected: LinkMode) -> Result<(), LiveIoError> {
    let actual = route.plan.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(LiveIoError::TransmissionModeMismatch { expected, actual })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoSendReport {
    pub bytes_sent: usize,
    pub wire_bytes: Option<Bytes>,
}

/// Unified packet-I/O seam used by the root client and test providers.
pub trait PacketIo: Send + Sync {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError>;
}

/// Native or injected Layer 2 transmission implementation.
pub trait Layer2Io: Send + Sync {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError>;
}

/// Native Layer 2 injection provider selected for the current target. Builds
/// without `native-layer2` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer2Io;

impl Layer2Io for SystemLayer2Io {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
        super::platform::system_send_layer2(frame)
    }
}

/// Native or injected raw Layer 3 transmission implementation.
pub trait Layer3Io: Send + Sync {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError>;
}

/// Native raw-IP provider selected for the current target. Builds without
/// `native-layer3` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer3Io;

impl Layer3Io for SystemLayer3Io {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError> {
        super::platform::system_send_layer3(frame)
    }
}

/// Composes independently owned Layer 2 and Layer 3 providers into `PacketIo`.
#[derive(Clone, Copy, Debug)]
pub struct DispatchPacketIo<L2, L3> {
    layer2: L2,
    layer3: L3,
}

impl<L2, L3> DispatchPacketIo<L2, L3> {
    pub fn new(layer2: L2, layer3: L3) -> Self {
        Self { layer2, layer3 }
    }

    pub fn layer2(&self) -> &L2 {
        &self.layer2
    }

    pub fn layer3(&self) -> &L3 {
        &self.layer3
    }

    pub fn into_parts(self) -> (L2, L3) {
        (self.layer2, self.layer3)
    }
}

impl<L2, L3> PacketIo for DispatchPacketIo<L2, L3>
where
    L2: Layer2Io,
    L3: Layer3Io,
{
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        match frame {
            TransmissionFrame::Layer2(frame) => self.layer2.send_layer2(frame),
            TransmissionFrame::Layer3(frame) => self.layer3.send_layer3(frame),
        }
    }
}

/// Whether delivered capture evidence is known to include every observed
/// frame within the configured capture scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureEvidenceCompleteness {
    Complete,
    Incomplete,
}

/// Backend capture counters. Received counters include frames accepted by the
/// owned capture session. Dropped counters describe frames/bytes lost before
/// delivery; receiver drops are the subset reported by the native capture
/// source, and overflow events count distinct bounded-queue observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStatistics {
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

impl CaptureStatistics {
    /// Validates counter arithmetic and required frame/byte relationships.
    pub fn validate(self) -> Result<Self, LiveIoError> {
        self.received_frames
            .checked_add(self.dropped_frames)
            .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                message: "received and dropped frame counters overflow u64".to_owned(),
            })?;
        self.received_bytes
            .checked_add(self.dropped_bytes)
            .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                message: "received and dropped byte counters overflow u64".to_owned(),
            })?;
        if self.dropped_frames == 0 && self.dropped_bytes != 0 {
            return Err(LiveIoError::InvalidCaptureStatistics {
                message: "dropped bytes were reported without a dropped frame".to_owned(),
            });
        }
        if self.receiver_dropped_frames > self.dropped_frames {
            return Err(LiveIoError::InvalidCaptureStatistics {
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
    pub fn evidence_completeness(self) -> CaptureEvidenceCompleteness {
        if self.has_loss() {
            CaptureEvidenceCompleteness::Incomplete
        } else {
            CaptureEvidenceCompleteness::Complete
        }
    }

    /// Converts incomplete evidence into its typed queue-loss or receiver-loss
    /// error. Complete statistics return `None`.
    pub fn evidence_loss_error(self) -> Option<LiveIoError> {
        if !self.has_loss() {
            None
        } else if self.overflow_events != 0 {
            Some(LiveIoError::CaptureQueueOverflow {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                overflow_events: self.overflow_events,
            })
        } else {
            Some(LiveIoError::CaptureEvidenceLoss {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                receiver_dropped_frames: self.receiver_dropped_frames,
            })
        }
    }
}

pub trait CaptureSession: Send {
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self) -> Result<(), LiveIoError>;
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError>;
    /// Stop the receiver and join all capture work before returning. An error
    /// means the implementation could not confirm complete cleanup.
    fn shutdown(&mut self) -> Result<(), LiveIoError>;
    /// Returns cumulative backend counters, including queue loss that was not
    /// otherwise observable through delivered frames.
    fn statistics(&self) -> CaptureStatistics;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureQueueLimits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub snap_length: usize,
    pub overflow_policy: CaptureOverflowPolicy,
}

impl Default for CaptureQueueLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            snap_length: DEFAULT_CAPTURE_SIZE_LIMIT,
            overflow_policy: CaptureOverflowPolicy::Fail,
        }
    }
}

impl CaptureQueueLimits {
    /// Validates non-zero limits, byte/snap consistency, and worst-case frame
    /// accounting before a backend allocates or starts capture.
    pub fn validate(self) -> Result<Self, LiveIoError> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("snap_length", self.snap_length),
        ] {
            if value == 0 {
                return Err(LiveIoError::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "must be greater than zero",
                });
            }
        }
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, DEFAULT_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, DEFAULT_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, DEFAULT_CAPTURE_SIZE_LIMIT),
        ] {
            if value > maximum {
                return Err(LiveIoError::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "exceeds the stable configured maximum",
                });
            }
        }
        if self.snap_length > self.max_bytes {
            return Err(LiveIoError::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: self.snap_length,
                reason: "cannot exceed max_bytes",
            });
        }
        self.max_frames.checked_mul(self.snap_length).ok_or(
            LiveIoError::InvalidCaptureQueueLimit {
                field: "max_frames * snap_length",
                value: self.max_frames,
                reason: "worst-case queue byte accounting overflows usize",
            },
        )?;
        Ok(self)
    }
}

pub(crate) fn validate_capture_timeout(timeout: Duration) -> Result<(), LiveIoError> {
    if timeout > MAX_CAPTURE_TIMEOUT {
        return Err(LiveIoError::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_CAPTURE_TIMEOUT,
        });
    }
    std::time::Instant::now()
        .checked_add(timeout)
        .map(|_| ())
        .ok_or(LiveIoError::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_CAPTURE_TIMEOUT,
        })
}

/// Starts an owned capture stream using platform-neutral route and limit data.
pub trait CaptureProvider: Send + Sync {
    type Capture: CaptureSession;

    fn arm_capture(
        &self,
        route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError>;
}

/// Owned native capture session. The native handle and capture worker remain
/// private behind this platform-neutral session wrapper.
pub struct SystemCaptureSession {
    inner: Box<dyn CaptureSession>,
}

impl SystemCaptureSession {
    pub(crate) fn new(inner: Box<dyn CaptureSession>) -> Self {
        Self { inner }
    }
}

impl CaptureSession for SystemCaptureSession {
    fn wait_ready(&mut self) -> Result<(), LiveIoError> {
        self.inner.wait_ready()
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
        validate_capture_timeout(timeout)?;
        self.inner.next_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.inner.shutdown()
    }

    fn statistics(&self) -> CaptureStatistics {
        self.inner.statistics()
    }
}

/// Native capture provider selected for the current target and the explicit
/// `native-layer2` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCaptureProvider;

impl CaptureProvider for SystemCaptureProvider {
    type Capture = SystemCaptureSession;

    fn arm_capture(
        &self,
        route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        super::platform::system_capture(route, limits).map(SystemCaptureSession::new)
    }
}

/// Complete exchange provider composed from packet transmission and capture.
pub trait ExchangeIo: PacketIo + CaptureProvider {}

impl<T> ExchangeIo for T where T: PacketIo + CaptureProvider {}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveIoError {
    #[error("live packet I/O is unavailable: {message}")]
    Unsupported { message: String },
    #[error("interface discovery failed: {message}")]
    InterfaceDiscovery { message: String },
    #[error("native dependency {dependency} is unavailable: {message}")]
    MissingDependency {
        dependency: &'static str,
        message: String,
    },
    #[error("network device {interface} is unavailable: {message}")]
    Device { interface: String, message: String },
    #[error("live packet I/O requires additional privileges: {message}")]
    Privilege { message: String },
    #[error("packet transmission failed: {message}")]
    Send { message: String },
    #[error(
        "packet transmission mode mismatch: expected {expected:?}, materialized route uses {actual:?}"
    )]
    TransmissionModeMismatch {
        expected: LinkMode,
        actual: LinkMode,
    },
    #[error("packet transmission route still has unresolved automatic link mode")]
    UnresolvedLinkMode,
    #[error(
        "packet transmission was incomplete: submitted {expected} bytes, backend reported {actual}"
    )]
    PartialSend { expected: usize, actual: usize },
    #[error(
        "packet transmission report is inconsistent: bytes_sent is {bytes_sent}, wire_bytes contains {wire_bytes} bytes"
    )]
    InvalidSendReport {
        bytes_sent: usize,
        wire_bytes: usize,
    },
    #[error("packet transmission wire evidence is inconsistent: {message}")]
    InvalidSendEvidence { message: String },
    #[error("Layer 2 envelope synthesis failed: {message}")]
    Encapsulation { message: String },
    #[error("raw Layer 3 frame is invalid for native transmission: {message}")]
    InvalidTransmissionFrame { message: String },
    #[error("capture failed: {message}")]
    Capture { message: String },
    #[error("capture did not become ready: {message}")]
    CaptureReadiness { message: String },
    #[error("capture timeout {timeout:?} is invalid; maximum is {maximum:?}")]
    InvalidCaptureTimeout {
        timeout: Duration,
        maximum: Duration,
    },
    #[error("invalid capture queue limit {field}={value}: {reason}")]
    InvalidCaptureQueueLimit {
        field: &'static str,
        value: usize,
        reason: &'static str,
    },
    #[error(
        "capture queue overflowed {overflow_events} time(s), dropping {dropped_frames} frame(s) / {dropped_bytes} byte(s)"
    )]
    CaptureQueueOverflow {
        dropped_frames: u64,
        dropped_bytes: u64,
        overflow_events: u64,
    },
    #[error(
        "capture evidence is incomplete: {dropped_frames} frame(s) / {dropped_bytes} byte(s) dropped, including {receiver_dropped_frames} receiver drop(s)"
    )]
    CaptureEvidenceLoss {
        dropped_frames: u64,
        dropped_bytes: u64,
        receiver_dropped_frames: u64,
    },
    #[error("capture backend returned invalid statistics: {message}")]
    InvalidCaptureStatistics { message: String },
}

impl ClassifiedError for LiveIoError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::Unsupported { .. } => ErrorClassification::new(
                "capability.unsupported",
                FailureKind::Capability,
                Some("enable and configure the requested native capability; PacketcraftR will not change transmission modes automatically"),
            ),
            Self::MissingDependency { .. } => ErrorClassification::new(
                "capability.missing_dependency",
                FailureKind::Capability,
                Some("install the named native dependency from its trusted platform source and retry"),
            ),
            Self::Privilege { .. } => ErrorClassification::new(
                "capability.privilege",
                FailureKind::Capability,
                Some("grant the minimum raw-socket or capture permission required by the selected platform adapter"),
            ),
            Self::InterfaceDiscovery { .. } => ErrorClassification::new(
                "io.interface_discovery",
                FailureKind::Io,
                Some("inspect the operating-system interface state and retry with an available interface"),
            ),
            Self::Device { .. } => ErrorClassification::new(
                "io.device",
                FailureKind::Io,
                Some("select an existing, enabled interface that supports the requested link mode"),
            ),
            Self::Send { .. } => ErrorClassification::new(
                "io.send",
                FailureKind::Io,
                Some("inspect the selected route, interface state, and platform socket restrictions before retrying"),
            ),
            Self::PartialSend { .. } => ErrorClassification::new(
                "io.partial_send",
                FailureKind::Io,
                Some("treat the operation as incomplete; do not retry without accounting for the attempted transmission"),
            ),
            Self::Capture { .. } => ErrorClassification::new(
                "io.capture",
                FailureKind::Io,
                Some("inspect the capture device state and native backend diagnostic before retrying"),
            ),
            Self::CaptureReadiness { .. } => ErrorClassification::new(
                "io.capture_readiness",
                FailureKind::Io,
                Some("fix capture startup before transmitting; capture-before-send readiness cannot be bypassed"),
            ),
            Self::CaptureQueueOverflow { .. } => ErrorClassification::new(
                "io.capture_overflow",
                FailureKind::Io,
                Some("treat the capture as incomplete or explicitly select a lossy overflow policy with visible statistics"),
            ),
            Self::CaptureEvidenceLoss { .. } => ErrorClassification::new(
                "io.capture_evidence_loss",
                FailureKind::Io,
                Some("treat the capture as incomplete; inspect receiver-drop counters and reduce native capture pressure before retrying"),
            ),
            Self::InvalidCaptureQueueLimit { .. } => ErrorClassification::new(
                "cli.capture_limit",
                FailureKind::Cli,
                Some("use non-zero capture limits whose snap length fits the aggregate byte ceiling"),
            ),
            Self::InvalidCaptureTimeout { .. } => ErrorClassification::new(
                "cli.capture_timeout",
                FailureKind::Cli,
                Some("use a finite capture wait no longer than the documented one-hour maximum"),
            ),
            Self::InvalidTransmissionFrame { .. } => ErrorClassification::new(
                "packet.transmission_frame",
                FailureKind::Packet,
                Some("rebuild a complete route-consistent IP datagram without fields the native kernel would rewrite"),
            ),
            Self::Encapsulation { .. } => ErrorClassification::new(
                "packet.encapsulation",
                FailureKind::Packet,
                Some("supply a complete link-layer envelope compatible with the materialized Layer 2 route"),
            ),
            Self::TransmissionModeMismatch { .. }
            | Self::UnresolvedLinkMode
            | Self::InvalidSendReport { .. }
            | Self::InvalidSendEvidence { .. }
            | Self::InvalidCaptureStatistics { .. } => ErrorClassification::new(
                "internal.live_io_invariant",
                FailureKind::Internal,
                Some("report the inconsistent provider result; do not reinterpret it as a successful operation"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_timeout_is_bounded_before_a_backend_wait() {
        assert!(validate_capture_timeout(MAX_CAPTURE_TIMEOUT).is_ok());
        let error = validate_capture_timeout(Duration::MAX).unwrap_err();
        assert!(matches!(
            &error,
            LiveIoError::InvalidCaptureTimeout {
                maximum: MAX_CAPTURE_TIMEOUT,
                ..
            }
        ));
        assert_eq!(error.classification().code, "cli.capture_timeout");
    }

    #[test]
    fn capture_completeness_and_loss_source_are_typed() {
        let receiver_loss = CaptureStatistics {
            dropped_frames: 2,
            receiver_dropped_frames: 2,
            ..CaptureStatistics::default()
        };
        assert_eq!(
            receiver_loss.validate().unwrap().evidence_completeness(),
            CaptureEvidenceCompleteness::Incomplete
        );
        assert!(matches!(
            receiver_loss.evidence_loss_error(),
            Some(LiveIoError::CaptureEvidenceLoss {
                receiver_dropped_frames: 2,
                ..
            })
        ));

        let invalid = CaptureStatistics {
            dropped_frames: 1,
            receiver_dropped_frames: 2,
            ..CaptureStatistics::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(LiveIoError::InvalidCaptureStatistics { .. })
        ));
    }
}
