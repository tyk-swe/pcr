// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-neutral contracts implemented by native and test I/O providers.

use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    CapturedFrame, InterfaceId, LinkCapability, LinkMode, LinkType, MacAddress, MaterializedRoute,
    PlannedRoute, DEFAULT_CAPTURE_SIZE_LIMIT,
};

/// Aggregate backend capture-queue capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte capacity used by default.
pub const DEFAULT_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;

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

/// Backend capture counters. Received counters include frames delivered to the
/// owned capture session; dropped counters describe frames/bytes lost before
/// delivery, and overflow events count distinct queue-overflow observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStatistics {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
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
        Ok(self)
    }

    /// Returns whether the backend reported any drop or queue overflow.
    pub fn has_loss(self) -> bool {
        self.dropped_frames != 0 || self.dropped_bytes != 0 || self.overflow_events != 0
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
    #[error("Layer 2 envelope synthesis failed: {message}")]
    Encapsulation { message: String },
    #[error("capture failed: {message}")]
    Capture { message: String },
    #[error("capture did not become ready: {message}")]
    CaptureReadiness { message: String },
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
    #[error("capture backend returned invalid statistics: {message}")]
    InvalidCaptureStatistics { message: String },
}
