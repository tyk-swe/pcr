// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one failure vocabulary every probe workflow reports, tagged with the
//! workflow that raised it so codes and messages stay workflow-specific.

use std::fmt;
use std::time::Duration;

use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use crate::BoundaryError;
use crate::probe::evidence::EvidenceDiagnosticDescriptor;

/// The probe workflows that share one lifecycle, error shape, and evidence
/// budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workflow {
    Scan,
    Traceroute,
}

impl Workflow {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
        }
    }

    /// The diagnostic codes the workflow emits when evidence is truncated.
    pub(crate) const fn evidence_diagnostics(self) -> EvidenceDiagnosticDescriptor {
        match self {
            Self::Scan => EvidenceDiagnosticDescriptor::new(
                "scan.evidence_limit",
                "scan.undecoded_limit",
                "scan",
            ),
            Self::Traceroute => EvidenceDiagnosticDescriptor::new(
                "traceroute.evidence_limit",
                "traceroute.undecoded_limit",
                "traceroute",
            ),
        }
    }

    /// What one executed batch is called in evidence errors.
    pub(crate) const fn batch_noun(self) -> &'static str {
        match self {
            Self::Scan => "batch",
            Self::Traceroute => "hop batch",
        }
    }

    const fn port_noun(self) -> &'static str {
        match self {
            Self::Scan => "ports",
            Self::Traceroute => "destination port",
        }
    }

    const fn codes(self) -> Codes {
        match self {
            Self::Scan => Codes {
                limit: "cli.scan_limit",
                limit_remediation: "use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits",
                family_remediation: "select a scan address family returned by the authorized target resolution",
                duration_limit: "policy.scan_duration_limit",
                duration_remediation: "reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                clock: "io.scan_clock",
                clock_remediation: "inspect the scan timer and account for probes already transmitted",
                evidence: "internal.scan_evidence",
                evidence_remediation: "treat the scan as incomplete because executor evidence was inconsistent",
            },
            Self::Traceroute => Codes {
                limit: "cli.traceroute_limit",
                limit_remediation: "use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits",
                family_remediation: "select a traceroute address family returned by the authorized target resolution",
                duration_limit: "policy.traceroute_duration_limit",
                duration_remediation: "reduce hops, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                clock: "io.traceroute_clock",
                clock_remediation: "inspect the traceroute timer and account for probes already transmitted",
                evidence: "internal.traceroute_evidence",
                evidence_remediation: "treat the trace as incomplete because executor evidence was inconsistent",
            },
        }
    }
}

impl fmt::Display for Workflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The published codes and remediations one workflow attaches to its errors.
struct Codes {
    limit: &'static str,
    limit_remediation: &'static str,
    family_remediation: &'static str,
    duration_limit: &'static str,
    duration_remediation: &'static str,
    clock: &'static str,
    clock_remediation: &'static str,
    evidence: &'static str,
    evidence_remediation: &'static str,
}

/// Why a probe workflow stopped, independent of which workflow it was.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    /// The requested port selection cannot be probed.
    InvalidPort {
        message: String,
    },
    InvalidTimeout {
        value: Duration,
        maximum: Duration,
    },
    InvalidDuration {
        value: Duration,
        maximum: Duration,
    },
    Authorization(BoundaryError),
    Family {
        family: &'static str,
    },
    DurationLimit {
        actual: Duration,
        limit: Duration,
    },
    Execution {
        sequence: u64,
        source: BoundaryError,
    },
    Clock {
        sequence: u64,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    InvalidEvidence {
        sequence: u64,
        message: String,
    },
    StatisticsOverflow {
        sequence: u64,
    },
    Output {
        source: BoundaryError,
    },
}

/// A probe workflow failure, reported under the workflow that raised it.
#[derive(Debug)]
pub struct Error {
    pub workflow: Workflow,
    pub kind: ErrorKind,
}

impl Error {
    #[must_use]
    pub const fn new(workflow: Workflow, kind: ErrorKind) -> Self {
        Self { workflow, kind }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let workflow = self.workflow;
        match &self.kind {
            ErrorKind::InvalidLimit {
                field,
                value,
                reason,
            } => write!(
                formatter,
                "invalid {workflow} limit {field}={value}: {reason}"
            ),
            ErrorKind::InvalidPort { message } => {
                write!(
                    formatter,
                    "invalid {workflow} {}: {message}",
                    workflow.port_noun()
                )
            }
            ErrorKind::InvalidTimeout { value, maximum } => write!(
                formatter,
                "{workflow} timeout {value:?} is invalid; maximum is {maximum:?}"
            ),
            ErrorKind::InvalidDuration { value, maximum } => write!(
                formatter,
                "{workflow} duration {value:?} is invalid; maximum is {maximum:?}"
            ),
            ErrorKind::Authorization(source) => {
                write!(formatter, "{workflow} authorization failed: {source}")
            }
            ErrorKind::Family { family } => write!(
                formatter,
                "resolved target has no {family} address selected for this {workflow}"
            ),
            ErrorKind::DurationLimit { actual, limit } => write!(
                formatter,
                "{workflow} worst-case duration {actual:?} exceeds the configured limit of {limit:?}"
            ),
            ErrorKind::Execution { sequence, source } => write!(
                formatter,
                "{workflow} execution failed at probe {sequence}: {source}"
            ),
            ErrorKind::Clock { sequence, .. } => {
                write!(
                    formatter,
                    "{workflow} rate clock failed before probe {sequence}"
                )
            }
            ErrorKind::InvalidEvidence { sequence, message } => write!(
                formatter,
                "{workflow} executor returned invalid evidence at probe {sequence}: {message}"
            ),
            ErrorKind::StatisticsOverflow { sequence } => write!(
                formatter,
                "{workflow} statistic accounting overflowed at probe {sequence}"
            ),
            ErrorKind::Output { source } => {
                write!(formatter, "{workflow} progressive output failed: {source}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Authorization(source)
            | ErrorKind::Execution { source, .. }
            | ErrorKind::Output { source } => Some(source),
            ErrorKind::Clock { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        let codes = self.workflow.codes();
        match &self.kind {
            ErrorKind::InvalidLimit { .. }
            | ErrorKind::InvalidPort { .. }
            | ErrorKind::InvalidTimeout { .. }
            | ErrorKind::InvalidDuration { .. } => {
                Classification::new(codes.limit, Kind::Cli, Some(codes.limit_remediation))
            }
            ErrorKind::Authorization(source)
            | ErrorKind::Execution { source, .. }
            | ErrorKind::Output { source } => source.classification(),
            ErrorKind::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some(codes.family_remediation),
            ),
            ErrorKind::DurationLimit { .. } => Classification::new(
                codes.duration_limit,
                Kind::Policy,
                Some(codes.duration_remediation),
            ),
            ErrorKind::Clock { .. } => {
                Classification::new(codes.clock, Kind::Io, Some(codes.clock_remediation))
            }
            ErrorKind::InvalidEvidence { .. } | ErrorKind::StatisticsOverflow { .. } => {
                Classification::new(
                    codes.evidence,
                    Kind::Internal,
                    Some(codes.evidence_remediation),
                )
            }
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match &self.kind {
            ErrorKind::Authorization(source) | ErrorKind::Output { source } => source.context(),
            ErrorKind::Execution { sequence, .. }
            | ErrorKind::Clock { sequence, .. }
            | ErrorKind::InvalidEvidence { sequence, .. }
            | ErrorKind::StatisticsOverflow { sequence } => {
                Some(Coordinate::ProbeSequence(*sequence))
            }
            _ => None,
        }
    }

    /// Boundary-sourced variants delegate because a [`BoundaryError`] carries
    /// a captured `causes` snapshot its own source chain no longer holds.
    fn causes(&self) -> Vec<String> {
        match &self.kind {
            ErrorKind::Authorization(source)
            | ErrorKind::Execution { source, .. }
            | ErrorKind::Output { source } => source.causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }
}

impl crate::target::GateErrors for Workflow {
    type Error = Error;

    fn duration_limit(&self, actual: Duration, limit: Duration) -> Error {
        Error::new(*self, ErrorKind::DurationLimit { actual, limit })
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::new(*self, ErrorKind::Authorization(source))
    }
}
