// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, DeadlineExceeded};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::Probe;
use super::WORKFLOW;
use super::report::PendingEvidence;
use crate::error::FromFailure as _;
use crate::target::{Family, SelectionError};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::{Error as LiveIoError, capture};

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    TargetSelection(SelectionError),
    Cancelled(Cancelled),
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    InvalidPort {
        message: String,
    },
    InvalidDiscovery {
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
    UnsupportedTcpRoute,
    MethodProbe {
        method: &'static str,
        probe: &'static str,
    },
    Authorization(BoundaryError),
    Family {
        family: &'static str,
    },
    DurationLimit {
        actual: Duration,
        limit: Duration,
    },
    Neighbor {
        address: std::net::IpAddr,
        source: BoundaryError,
    },
    PipelineExecution {
        source: BoundaryError,
    },
    PipelineFailure(Box<PipelineFailure>),
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
    IncoherentEvents {
        message: String,
    },
}

impl From<Cancelled> for Error {
    fn from(source: Cancelled) -> Self {
        Self::Cancelled(source)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetSelection(source) => source.fmt(f),
            Self::Cancelled(source) => source.fmt(f),
            Self::InvalidLimit {
                field,
                value,
                reason,
            } => write!(f, "invalid scan limit {field}={value}: {reason}"),
            Self::InvalidPort { message } => write!(f, "invalid scan ports: {message}"),
            Self::InvalidDiscovery { message } => write!(f, "invalid host discovery: {message}"),
            Self::InvalidTimeout { value, maximum } => {
                write!(
                    f,
                    "scan timeout {value:?} is invalid; maximum is {maximum:?}"
                )
            }
            Self::InvalidDuration { value, maximum } => {
                write!(
                    f,
                    "scan duration {value:?} is invalid; maximum is {maximum:?}"
                )
            }
            Self::UnsupportedTcpRoute => {
                f.write_str("TCP connect uses kernel route and source selection")
            }
            Self::MethodProbe { method, probe } => {
                write!(f, "the {method} scan method cannot send {probe} probes")
            }
            Self::Authorization(_) => f.write_str("scan authorization failed"),
            Self::Family { family } => {
                write!(
                    f,
                    "resolved target has no {family} address selected for this scan"
                )
            }
            Self::DurationLimit { actual, limit } => write!(
                f,
                "scan worst-case duration {actual:?} exceeds the configured limit of {limit:?}"
            ),
            Self::Neighbor { address, .. } => {
                write!(f, "resolving the neighbor of {address} failed")
            }
            Self::PipelineExecution { .. } | Self::PipelineFailure(_) => {
                f.write_str("scan pipeline execution failed")
            }
            Self::Execution { sequence, .. } => {
                write!(f, "scan execution failed at probe {sequence}")
            }
            Self::Clock { sequence, .. } => {
                write!(f, "scan rate clock failed before probe {sequence}")
            }
            Self::InvalidEvidence { sequence, message } => write!(
                f,
                "scan executor returned invalid evidence at probe {sequence}: {message}"
            ),
            Self::StatisticsOverflow { sequence } => {
                write!(
                    f,
                    "scan statistic accounting overflowed at probe {sequence}"
                )
            }
            Self::Output { .. } => f.write_str("scan progressive output failed"),
            Self::IncoherentEvents { message } => {
                write!(f, "scan events are incoherent: {message}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TargetSelection(source) => source.source(),
            Self::Cancelled(source) => source.source(),
            Self::Authorization(source)
            | Self::Neighbor { source, .. }
            | Self::PipelineExecution { source }
            | Self::Execution { source, .. }
            | Self::Output { source } => Some(source),
            Self::PipelineFailure(failure) => Some(failure.as_ref()),
            Self::Clock { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("packet scan pipeline failed")]
pub struct PipelineFailure {
    #[source]
    pub source: BoundaryError,
    pub stats: crate::Stats,
    pub pending: Vec<PendingEvidence>,
    pub failed_probe: Option<Probe>,
    pub capture_sources: Vec<capture::Source>,
    pub cleanup: Option<Box<LiveIoError>>,
}
impl Classified for PipelineFailure {
    fn classification(&self) -> Classification {
        self.source.classification()
    }
    fn causes(&self) -> Vec<String> {
        let mut causes = self.source.as_causes();
        if let Some(cleanup) = &self.cleanup {
            causes.push(cleanup.to_string());
            causes.extend(cleanup.causes());
        }
        causes
    }
    fn context(&self) -> Option<Coordinate> {
        self.failed_probe
            .as_ref()
            .map(|probe| Coordinate::ProbeSequence(probe.sequence))
            .or_else(|| self.source.context())
    }
}

#[derive(Debug)]
pub(crate) enum PipelineRunError {
    Setup(BoundaryError),
    Failure(Box<PipelineFailure>),
}

impl From<BoundaryError> for PipelineRunError {
    fn from(source: BoundaryError) -> Self {
        Self::Setup(source)
    }
}

impl std::fmt::Display for PipelineRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(source) => source.fmt(f),
            Self::Failure(failure) => failure.fmt(f),
        }
    }
}

impl std::error::Error for PipelineRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Setup(source) => source.source(),
            Self::Failure(failure) => Some(failure.as_ref()),
        }
    }
}

impl Classified for PipelineRunError {
    fn classification(&self) -> Classification {
        match self {
            Self::Setup(source) => source.classification(),
            Self::Failure(failure) => failure.classification(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Setup(source) => source.context(),
            Self::Failure(failure) => failure.context(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Setup(source) => source.as_causes(),
            Self::Failure(failure) => failure.causes(),
        }
    }
}

impl From<PipelineRunError> for Error {
    fn from(error: PipelineRunError) -> Self {
        match error {
            PipelineRunError::Setup(source) => Self::PipelineExecution { source },
            PipelineRunError::Failure(failure) => Self::PipelineFailure(failure),
        }
    }
}

packetcraftr_core::deadline_error_conversions!(Error);

impl Error {
    pub(super) fn family(family: Family) -> Self {
        Self::Family {
            family: family.label(),
        }
    }

    /// Returns retained partial pipeline evidence when a pipelined scan failed mid-run.
    #[must_use]
    pub fn pipeline_failure(&self) -> Option<&PipelineFailure> {
        match self {
            Self::PipelineFailure(failure) => Some(failure),
            _ => None,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::TargetSelection(source) => source.classification(),
            Self::UnsupportedTcpRoute => Classification::new(
                crate::code::CapabilityScanTcpRoute,
                Kind::Capability,
                Some("omit packet interface/source/link overrides for ordinary TCP"),
            ),
            Self::MethodProbe { .. } => Classification::new(
                crate::code::CliScanMethod,
                Kind::Usage,
                Some("probe UDP and ICMP endpoints and discover neighbors with the raw method"),
            ),
            Self::InvalidDiscovery { .. } => Classification::new(
                crate::code::CliScanDiscovery,
                Kind::Usage,
                Some(
                    "select discovery probes only when discovery runs, and no scan ports with discovery only",
                ),
            ),
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                crate::code::CliScanLimit,
                Kind::Usage,
                Some(
                    "use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits",
                ),
            ),
            Self::Authorization(source)
            | Self::Neighbor { source, .. }
            | Self::PipelineExecution { source }
            | Self::Execution { source, .. }
            | Self::Output { source } => source.classification(),
            Self::PipelineFailure(failure) => failure.classification(),
            Self::Family { .. } => Classification::new(
                crate::code::PacketTargetAddressFamily,
                Kind::Packet,
                Some("select a scan address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                crate::code::PolicyScanDurationLimit,
                Kind::Policy,
                Some(
                    "reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Clock { .. } => Classification::new(
                crate::code::IoScanClock,
                Kind::Io,
                Some("inspect the scan timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                crate::code::InternalScanEvidence,
                Kind::Internal,
                Some("treat the scan as incomplete because executor evidence was inconsistent"),
            ),
            Self::IncoherentEvents { .. } => Classification::new(
                crate::code::InternalScanEventCoherence,
                Kind::Internal,
                Some("collect every scan event once, from one scan, in publication order"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(source)
            | Self::Neighbor { source, .. }
            | Self::Output { source }
            | Self::PipelineExecution { source } => source.context(),
            Self::PipelineFailure(failure) => failure.context(),
            Self::Execution { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::StatisticsOverflow { sequence } => Some(Coordinate::ProbeSequence(*sequence)),
            _ => None,
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(source)
            | Self::Neighbor { source, .. }
            | Self::PipelineExecution { source }
            | Self::Execution { source, .. }
            | Self::Output { source } => source.as_causes(),
            Self::PipelineFailure(failure) => failure.causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }
}

crate::error::impl_from_failure!(Error, workflow: WORKFLOW);

pub(super) fn duration_limit(sequence: u64, error: DeadlineExceeded) -> Error {
    Error::from_failure(sequence, crate::error::Failure::DurationLimit(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_failure_accessor_returns_typed_partial_evidence() {
        let failure = PipelineFailure {
            source: BoundaryError::from_error(Error::UnsupportedTcpRoute),
            stats: crate::Stats::default(),
            pending: Vec::new(),
            failed_probe: None,
            capture_sources: Vec::new(),
            cleanup: None,
        };
        let error = Error::from(PipelineRunError::Failure(Box::new(failure)));
        assert!(error.pipeline_failure().is_some());
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<PipelineFailure>())
                .is_some()
        );
        assert_eq!(
            error.classification().code,
            crate::code::CapabilityScanTcpRoute
        );
        assert!(Error::UnsupportedTcpRoute.pipeline_failure().is_none());
    }
}
