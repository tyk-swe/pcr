// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error as ThisError;

use super::capture::Phase as CapturePhase;
use super::interface::Id as InterfaceId;
use super::link::Mode;
use packetcraftr_core::error::{Classification, Classified, Kind, Source, source_chain};

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

/// Live interface, transmission, and capture failures.
///
/// A native failure keeps the platform's own error as its `source`, a shared
/// [`Source`] handle so capture sessions can return a terminal failure
/// repeatedly. An absent source means a PacketcraftR check of a provider's
/// answer failed rather than a platform call.
#[derive(Debug, ThisError, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error("live packet I/O is unavailable: {message}")]
    Unsupported {
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("interface discovery failed: {message}")]
    InterfaceDiscovery {
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("native dependency {dependency} is unavailable: {message}")]
    MissingDependency {
        dependency: &'static str,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("network device {interface} is unavailable: {message}")]
    Device {
        interface: String,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("live packet I/O requires additional privileges: {message}")]
    Privilege {
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("packet transmission failed: {message}")]
    Send {
        message: String,
        #[source]
        source: Option<Source>,
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
        source: Option<Source>,
    },
    #[error("native capture filter was rejected for {interface}: {message}")]
    InvalidCaptureFilter { interface: String, message: String },
    #[error("capture filter is {length} bytes; the maximum is {maximum}")]
    CaptureFilterTooLong { length: usize, maximum: usize },
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
    #[error("invalid native capture setting {field}: {message}")]
    InvalidCaptureSetting {
        field: &'static str,
        message: String,
    },
    /// `message` is boxed so this variant stays no larger than the other
    /// two-`String` variants the `Error` enum is sized for.
    #[error("capture setting {setting} is not supported on {interface}: {message}")]
    UnsupportedCaptureSetting {
        setting: &'static str,
        interface: String,
        message: Box<str>,
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
    #[error("invalid capture group: {reason}")]
    InvalidCaptureGroup { reason: &'static str },
    /// One source of a capture group failed; `source` is that session's own
    /// failure and decides the classification.
    #[error("capture source {index} ({}) failed during {phase}", .interface.name)]
    CaptureSource {
        index: usize,
        interface: InterfaceId,
        phase: CapturePhase,
        #[source]
        source: Box<Self>,
    },
    #[error("capture source {index} broke its provider contract: {reason}")]
    CaptureSourceContract { index: usize, reason: &'static str },
    #[error("capture group is not armed, not ready, or has been shut down")]
    CaptureGroupState,
    /// Stopping a capture group failed for more than one source: `first` in
    /// source order, then every `remaining` failure.
    #[error("capture group cleanup failed for {} sources", .remaining.len() + 1)]
    CaptureCleanup {
        #[source]
        first: Box<Self>,
        remaining: Vec<Self>,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
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
            Self::CaptureFilterTooLong { .. } => classified_cli(
                "cli.capture_filter",
                "shorten the capture filter to the documented 64 KiB maximum",
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
            Self::InvalidCaptureSetting { .. } => classified_cli(
                "cli.capture_setting",
                "use a finite in-range value or drop the explicit native capture setting",
            ),
            Self::UnsupportedCaptureSetting { .. } => classified(
                "capability.capture_setting",
                Kind::Capability,
                "remove the setting or select a value the interface supports; the interfaces command lists advertised timestamp types",
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
            Self::InvalidCaptureGroup { .. } => classified_cli(
                "cli.capture_group",
                "select 1 to 16 distinct interfaces whose shared queue limits hold one full snapshot each",
            ),
            Self::CaptureSourceContract { .. } | Self::CaptureGroupState => classified(
                "internal.capture_group",
                Kind::Internal,
                "report the inconsistent capture provider or call order; do not treat the capture as complete",
            ),
            Self::CaptureSource { source, .. } => source.classification(),
            Self::CaptureCleanup { first, .. } => first.classification(),
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

    /// A multi-source cleanup failure lists every remaining failure after the
    /// first one's source chain.
    fn causes(&self) -> Vec<String> {
        let mut causes = source_chain(self);
        if let Self::CaptureCleanup { remaining, .. } = self {
            for failure in remaining {
                causes.push(failure.to_string());
                causes.extend(failure.causes());
            }
        }
        causes
    }
}

impl Error {
    /// The failure a provider reports when its caller's deadline stopped it
    /// while `operation` was in progress.
    #[cfg(native_layer2)]
    pub(crate) fn interrupted(
        interrupted: packetcraftr_core::budget::Interrupted,
        operation: &'static str,
    ) -> Self {
        match interrupted {
            packetcraftr_core::budget::Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded { operation },
        }
    }
}

fn classified(code: &'static str, kind: Kind, remediation: &'static str) -> Classification {
    Classification::new(code, kind, Some(remediation))
}

fn classified_cli(code: &'static str, remediation: &'static str) -> Classification {
    classified(code, Kind::Usage, remediation)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::Error;

    #[track_caller]
    pub(crate) fn assert_same_failure(actual: &Error, expected: &Error) {
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}
