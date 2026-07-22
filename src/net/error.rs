// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error as ThisError;

use super::link::LinkMode;
use crate::error::{Classification, Classified, Kind};

/// Errors shared by live interface, transmission, and capture providers.
#[derive(Debug, ThisError, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
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
    #[error(
        "active exchange capture cannot provide monotonic ingress timestamps required for freshness correlation"
    )]
    MissingMonotonicCaptureTimestamp,
    #[error("live operation deadline expired while {operation}")]
    DeadlineExceeded { operation: &'static str },
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

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Unsupported { .. } => Classification::new(
                "capability.unsupported",
                Kind::Capability,
                Some(
                    "enable and configure the requested native capability; PacketcraftR will not change transmission modes automatically",
                ),
            ),
            Self::MissingDependency { .. } => Classification::new(
                "capability.missing_dependency",
                Kind::Capability,
                Some(
                    "install the named native dependency from its trusted platform source and retry",
                ),
            ),
            Self::Privilege { .. } => Classification::new(
                "capability.privilege",
                Kind::Capability,
                Some(
                    "grant the minimum raw-socket or capture permission required by the selected platform adapter",
                ),
            ),
            Self::InterfaceDiscovery { .. } => Classification::new(
                "io.interface_discovery",
                Kind::Io,
                Some(
                    "inspect the operating-system interface state and retry with an available interface",
                ),
            ),
            Self::Device { .. } => Classification::new(
                "io.device",
                Kind::Io,
                Some("select an existing, enabled interface that supports the requested link mode"),
            ),
            Self::Send { .. } => Classification::new(
                "io.send",
                Kind::Io,
                Some(
                    "inspect the selected route, interface state, and platform socket restrictions before retrying",
                ),
            ),
            Self::PartialSend { .. } => Classification::new(
                "io.partial_send",
                Kind::Io,
                Some(
                    "treat the operation as incomplete; do not retry without accounting for the attempted transmission",
                ),
            ),
            Self::Capture { .. } => Classification::new(
                "io.capture",
                Kind::Io,
                Some(
                    "inspect the capture device state and native backend diagnostic before retrying",
                ),
            ),
            Self::CaptureReadiness { .. } => Classification::new(
                "io.capture_readiness",
                Kind::Io,
                Some(
                    "fix capture startup before transmitting; capture-before-send readiness cannot be bypassed",
                ),
            ),
            Self::MissingMonotonicCaptureTimestamp => Classification::new(
                "capability.capture_monotonic_ingress_time",
                Kind::Capability,
                Some(
                    "use a capture session that records monotonic ingress timestamps before sending active probes",
                ),
            ),
            Self::DeadlineExceeded { .. } => Classification::new(
                "io.deadline_exceeded",
                Kind::Io,
                Some(
                    "increase the finite operation timeout or reduce readiness, send, and capture work",
                ),
            ),
            Self::CaptureQueueOverflow { .. } => Classification::new(
                "io.capture_overflow",
                Kind::Io,
                Some(
                    "treat the capture as incomplete or explicitly select a lossy overflow policy with visible statistics",
                ),
            ),
            Self::CaptureEvidenceLoss { .. } => Classification::new(
                "io.capture_evidence_loss",
                Kind::Io,
                Some(
                    "treat the capture as incomplete; inspect receiver-drop counters and reduce native capture pressure before retrying",
                ),
            ),
            Self::InvalidCaptureQueueLimit { .. } => Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some(
                    "use non-zero capture limits whose snap length fits the aggregate byte ceiling",
                ),
            ),
            Self::InvalidCaptureTimeout { .. } => Classification::new(
                "cli.capture_timeout",
                Kind::Cli,
                Some("use a finite capture wait no longer than the documented one-hour maximum"),
            ),
            Self::InvalidTransmissionFrame { .. } => Classification::new(
                "packet.transmission_frame",
                Kind::Packet,
                Some(
                    "rebuild a complete route-consistent IP datagram without fields the native kernel would rewrite",
                ),
            ),
            Self::Encapsulation { .. } => Classification::new(
                "packet.encapsulation",
                Kind::Packet,
                Some(
                    "supply a complete link-layer envelope compatible with the materialized Layer 2 route",
                ),
            ),
            Self::TransmissionModeMismatch { .. }
            | Self::UnresolvedLinkMode
            | Self::InvalidSendReport { .. }
            | Self::InvalidSendEvidence { .. }
            | Self::InvalidCaptureStatistics { .. } => Classification::new(
                "internal.live_io_invariant",
                Kind::Internal,
                Some(
                    "report the inconsistent provider result; do not reinterpret it as a successful operation",
                ),
            ),
        }
    }
}
