// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error as ThisError;

use super::link::Mode;
use packetcraftr_core::error::{Classification, Classified, Kind};

/// The system or backend failure a live-I/O error retains.
///
/// Shared rather than boxed so [`Error`] stays `Clone` — a capture session
/// stores its terminal failure and hands it to every later caller — while
/// still retaining `io::Error`, `pcap::Error`, and the platform loader
/// failures, none of which are `Clone`. `None` means the refusal is
/// PacketcraftR's own invariant rather than something the platform reported.
pub type SystemFault = Arc<dyn StdError + Send + Sync>;

/// Which exact-transmission invariant a provider's wire evidence violated.
///
/// Each variant is one unrelated failure: they are never interchangeable and
/// never distinguished by inspecting a message.
#[derive(Debug, ThisError, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendEvidenceFault {
    #[error("provider-accepted bytes differ from the exact submitted frame")]
    AcceptedBytesDiffer,
    #[error("provider timing has inconsistent monotonic endpoints")]
    InconsistentTiming,
    #[error("provider-accepted bytes cannot form a capture record: {0}")]
    UnrepresentableFrame(#[from] packetcraftr_core::frame::Error),
}

/// Errors shared by live interface, transmission, and capture providers.
///
/// The variants a native adapter raises retain the platform failure they were
/// given as a [`SystemFault`] rather than formatting it into `message`, so the
/// typed refusal survives to the render boundary. That source is not
/// comparable, so these failures are matched on rather than equated.
#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error("live packet I/O is unavailable: {message}")]
    Unsupported {
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error("interface discovery failed: {message}")]
    InterfaceDiscovery {
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error("native dependency {dependency} is unavailable: {message}")]
    MissingDependency {
        dependency: &'static str,
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error("network device {interface} is unavailable: {message}")]
    Device {
        interface: String,
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error("live packet I/O requires additional privileges: {message}")]
    Privilege {
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error("packet transmission failed: {message}")]
    Send {
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
    #[error(
        "packet transmission mode mismatch: expected {expected:?}, materialized route uses {actual:?}"
    )]
    TransmissionModeMismatch { expected: Mode, actual: Mode },
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
    #[error("packet transmission wire evidence is inconsistent: {fault}")]
    InvalidSendEvidence {
        #[source]
        fault: SendEvidenceFault,
    },
    #[error("raw Layer 3 frame is invalid for native transmission: {message}")]
    InvalidTransmissionFrame { message: String },
    #[error("capture failed: {message}")]
    Capture {
        message: String,
        #[source]
        source: Option<SystemFault>,
    },
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
            Self::Unsupported { .. } => classified(
                "capability.unsupported",
                Kind::Capability,
                "enable and configure the requested native capability; PacketcraftR will not change transmission modes automatically",
            ),
            Self::MissingDependency { .. } => classified(
                "capability.missing_dependency",
                Kind::Capability,
                "install the named native dependency from its trusted platform source and retry",
            ),
            Self::Privilege { .. } => classified(
                "capability.privilege",
                Kind::Capability,
                "grant the minimum raw-socket or capture permission required by the selected platform adapter",
            ),
            Self::InterfaceDiscovery { .. } => classified(
                "io.interface_discovery",
                Kind::Io,
                "inspect the operating-system interface state and retry with an available interface",
            ),
            Self::Device { .. } => classified(
                "io.device",
                Kind::Io,
                "select an existing, enabled interface that supports the requested link mode",
            ),
            Self::Send { .. } => classified(
                "io.send",
                Kind::Io,
                "inspect the selected route, interface state, and platform socket restrictions before retrying",
            ),
            Self::PartialSend { .. } => classified(
                "io.partial_send",
                Kind::Io,
                "treat the operation as incomplete; do not retry without accounting for the attempted transmission",
            ),
            Self::Capture { .. } => classified(
                "io.capture",
                Kind::Io,
                "inspect the capture device state and native backend diagnostic before retrying",
            ),
            Self::InvalidCaptureFilter { .. } => classified_cli(
                "cli.capture_filter",
                "use a valid libpcap/Npcap BPF capture-filter expression",
            ),
            Self::CaptureFilterInstallation { .. } => classified(
                "io.capture_filter",
                Kind::Io,
                "inspect the selected interface and native backend diagnostic before retrying",
            ),
            Self::CaptureReadiness { .. } => classified(
                "io.capture_readiness",
                Kind::Io,
                "fix capture startup before transmitting; capture-before-send readiness cannot be bypassed",
            ),
            Self::DeadlineExceeded { .. } => classified(
                "io.deadline_exceeded",
                Kind::Io,
                "increase the finite operation timeout or reduce readiness, send, and capture work",
            ),
            Self::CaptureQueueOverflow { .. } => classified(
                "io.capture_overflow",
                Kind::Io,
                "treat the capture as incomplete or explicitly select a lossy overflow policy with visible statistics",
            ),
            Self::CaptureEvidenceLoss { .. } => classified(
                "io.capture_evidence_loss",
                Kind::Io,
                "treat the capture as incomplete; inspect receiver-drop counters and reduce native capture pressure before retrying",
            ),
            Self::InvalidCaptureQueueLimit { .. } => classified_cli(
                "cli.capture_limit",
                "use non-zero capture limits whose snap length fits the aggregate byte ceiling",
            ),
            Self::InvalidCaptureTimeout { .. } => classified_cli(
                "cli.capture_timeout",
                "use a finite capture wait no longer than the documented one-hour maximum",
            ),
            Self::InvalidTransmissionFrame { .. } => classified(
                "packet.transmission_frame",
                Kind::Packet,
                "rebuild a complete route-consistent IP datagram without fields the native kernel would rewrite",
            ),
            Self::TransmissionModeMismatch { .. }
            | Self::UnresolvedLinkMode
            | Self::InvalidSendReport { .. }
            | Self::InvalidSendEvidence { .. }
            | Self::InvalidCaptureStatistics { .. } => classified(
                "internal.live_io_invariant",
                Kind::Internal,
                "report the inconsistent provider result; do not reinterpret it as a successful operation",
            ),
        }
    }
}

fn classified(code: &'static str, kind: Kind, remediation: &'static str) -> Classification {
    Classification::new(code, kind, Some(remediation))
}

fn classified_cli(code: &'static str, remediation: &'static str) -> Classification {
    classified(code, Kind::Cli, remediation)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Error;

    /// Whether two failures are the same failure, field by field.
    ///
    /// A retained [`SystemFault`](super::SystemFault) is not comparable, so
    /// `Error` derives no `PartialEq`. `Debug` renders every field, the source
    /// included, which compares strictly more than a derived `==` did.
    #[must_use]
    pub(crate) fn same_failure(left: &Error, right: &Error) -> bool {
        format!("{left:?}") == format!("{right:?}")
    }

    /// [`same_failure`] as an assertion, reporting both renderings on failure.
    #[track_caller]
    pub(crate) fn assert_same_failure(actual: &Error, expected: &Error) {
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}
