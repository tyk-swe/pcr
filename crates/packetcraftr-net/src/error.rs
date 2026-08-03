// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error as ThisError;

use super::link::LinkMode;
use packetcraftr_core::error::{Classification, Classified, Kind};

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
    #[error("native capture filter was rejected for {interface}: {message}")]
    InvalidCaptureFilter { interface: String, message: String },
    #[error("native capture filter installation failed for {interface}: {message}")]
    CaptureFilterInstallation { interface: String, message: String },
    #[error("capture did not become ready: {message}")]
    CaptureReadiness { message: String },
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
            Self::InvalidCaptureFilter { .. } => Classification::new(
                "cli.capture_filter",
                Kind::Cli,
                Some("use a valid libpcap/Npcap BPF capture-filter expression"),
            ),
            Self::CaptureFilterInstallation { .. } => Classification::new(
                "io.capture_filter",
                Kind::Io,
                Some(
                    "inspect the selected interface and native backend diagnostic before retrying",
                ),
            ),
            Self::CaptureReadiness { .. } => Classification::new(
                "io.capture_readiness",
                Kind::Io,
                Some(
                    "fix capture startup before transmitting; capture-before-send readiness cannot be bypassed",
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use packetcraftr_core::error::{Classified, Kind};

    use super::Error;
    use crate::link::LinkMode;

    #[test]
    fn every_live_io_error_has_a_stable_classification_family() {
        let cases = [
            (
                Error::Unsupported {
                    message: "disabled".to_owned(),
                },
                "capability.unsupported",
                Kind::Capability,
            ),
            (
                Error::InterfaceDiscovery {
                    message: "failed".to_owned(),
                },
                "io.interface_discovery",
                Kind::Io,
            ),
            (
                Error::MissingDependency {
                    dependency: "pcap",
                    message: "missing".to_owned(),
                },
                "capability.missing_dependency",
                Kind::Capability,
            ),
            (
                Error::Device {
                    interface: "test0".to_owned(),
                    message: "down".to_owned(),
                },
                "io.device",
                Kind::Io,
            ),
            (
                Error::Privilege {
                    message: "denied".to_owned(),
                },
                "capability.privilege",
                Kind::Capability,
            ),
            (
                Error::Send {
                    message: "failed".to_owned(),
                },
                "io.send",
                Kind::Io,
            ),
            (
                Error::TransmissionModeMismatch {
                    expected: LinkMode::Layer2,
                    actual: LinkMode::Layer3,
                },
                "internal.live_io_invariant",
                Kind::Internal,
            ),
            (
                Error::UnresolvedLinkMode,
                "internal.live_io_invariant",
                Kind::Internal,
            ),
            (
                Error::PartialSend {
                    expected: 10,
                    actual: 9,
                },
                "io.partial_send",
                Kind::Io,
            ),
            (
                Error::InvalidSendReport {
                    bytes_sent: 1,
                    wire_bytes: 2,
                },
                "internal.live_io_invariant",
                Kind::Internal,
            ),
            (
                Error::InvalidSendEvidence {
                    message: "mismatch".to_owned(),
                },
                "internal.live_io_invariant",
                Kind::Internal,
            ),
            (
                Error::Encapsulation {
                    message: "invalid".to_owned(),
                },
                "packet.encapsulation",
                Kind::Packet,
            ),
            (
                Error::InvalidTransmissionFrame {
                    message: "invalid".to_owned(),
                },
                "packet.transmission_frame",
                Kind::Packet,
            ),
            (
                Error::Capture {
                    message: "failed".to_owned(),
                },
                "io.capture",
                Kind::Io,
            ),
            (
                Error::InvalidCaptureFilter {
                    interface: "test0".to_owned(),
                    message: "syntax error".to_owned(),
                },
                "cli.capture_filter",
                Kind::Cli,
            ),
            (
                Error::CaptureFilterInstallation {
                    interface: "test0".to_owned(),
                    message: "backend failure".to_owned(),
                },
                "io.capture_filter",
                Kind::Io,
            ),
            (
                Error::CaptureReadiness {
                    message: "not ready".to_owned(),
                },
                "io.capture_readiness",
                Kind::Io,
            ),
            (
                Error::DeadlineExceeded { operation: "send" },
                "io.deadline_exceeded",
                Kind::Io,
            ),
            (
                Error::InvalidCaptureTimeout {
                    timeout: Duration::from_secs(2),
                    maximum: Duration::from_secs(1),
                },
                "cli.capture_timeout",
                Kind::Cli,
            ),
            (
                Error::InvalidCaptureQueueLimit {
                    field: "max_frames",
                    value: 0,
                    reason: "must be non-zero",
                },
                "cli.capture_limit",
                Kind::Cli,
            ),
            (
                Error::CaptureQueueOverflow {
                    dropped_frames: 1,
                    dropped_bytes: 10,
                    overflow_events: 1,
                },
                "io.capture_overflow",
                Kind::Io,
            ),
            (
                Error::CaptureEvidenceLoss {
                    dropped_frames: 1,
                    dropped_bytes: 10,
                    receiver_dropped_frames: 1,
                },
                "io.capture_evidence_loss",
                Kind::Io,
            ),
            (
                Error::InvalidCaptureStatistics {
                    message: "invalid".to_owned(),
                },
                "internal.live_io_invariant",
                Kind::Internal,
            ),
        ];

        for (error, code, kind) in cases {
            let classification = error.classification();
            assert_eq!(classification.code, code);
            assert_eq!(classification.kind, kind);
            assert!(classification.remediation.is_some());
            assert!(!error.to_string().is_empty());
        }
    }
}
