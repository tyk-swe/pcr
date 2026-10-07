// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::Probe;
use super::WORKFLOW;
use super::report::PendingEvidence;
use crate::StatsOverflow;
use crate::target::{Family, SelectionError};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::{Error as LiveIoError, capture};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    TargetSelection(SelectionError),
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("invalid scan limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid scan ports: {message}")]
    InvalidPort { message: String },
    #[error("scan timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("scan duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("TCP connect uses kernel route and source selection")]
    UnsupportedTcpRoute,
    #[error("the {method} scan method cannot probe {transport} endpoints")]
    MethodTransport {
        method: &'static str,
        transport: &'static str,
    },
    #[error("scan authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("resolved target has no {family} address selected for this scan")]
    Family { family: &'static str },
    #[error("scan worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("scan pipeline execution failed")]
    PipelineExecution {
        #[source]
        source: BoundaryError,
    },
    #[error("scan execution failed at probe {sequence}")]
    Execution {
        sequence: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("scan rate clock failed before probe {sequence}")]
    Clock {
        sequence: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("scan executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("scan statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
    #[error("scan progressive output failed")]
    Output {
        #[source]
        source: BoundaryError,
    },
    #[error("scan events are incoherent: {message}")]
    IncoherentEvents { message: String },
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

crate::deadline::deadline_error_conversions!(Error);

impl Error {
    pub(super) fn family(family: Family) -> Self {
        Self::Family {
            family: family.label(),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::TargetSelection(source) => source.classification(),
            Self::UnsupportedTcpRoute => Classification::new(
                "capability.scan_tcp_route",
                Kind::Capability,
                Some("omit packet interface/source/link overrides for ordinary TCP"),
            ),
            Self::MethodTransport { .. } => Classification::new(
                "cli.scan_method",
                Kind::Usage,
                Some("probe UDP and ICMP endpoints with the raw method"),
            ),
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.scan_limit",
                Kind::Usage,
                Some(
                    "use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits",
                ),
            ),
            Self::Authorization(source)
            | Self::PipelineExecution { source }
            | Self::Execution { source, .. }
            | Self::Output { source } => source.classification(),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a scan address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.scan_duration_limit",
                Kind::Policy,
                Some(
                    "reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Clock { .. } => Classification::new(
                "io.scan_clock",
                Kind::Io,
                Some("inspect the scan timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.scan_evidence",
                Kind::Internal,
                Some("treat the scan as incomplete because executor evidence was inconsistent"),
            ),
            Self::IncoherentEvents { .. } => Classification::new(
                "internal.scan_event_coherence",
                Kind::Internal,
                Some("collect every scan event once, from one scan, in publication order"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(source)
            | Self::Output { source }
            | Self::PipelineExecution { source } => source.context(),
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
            | Self::PipelineExecution { source }
            | Self::Execution { source, .. }
            | Self::Output { source } => source.as_causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Probes;

impl crate::execution::Errors for Probes {
    type Error = Error;
    type Step = u64;

    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Error {
        Error::InvalidLimit {
            field,
            value,
            reason,
        }
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::Authorization(source)
    }

    fn duration_limit(&self, _sequence: u64, source: DeadlineExceeded) -> Error {
        source.into()
    }

    fn interrupted(&self, _sequence: u64, source: Interrupted) -> Error {
        source.into()
    }

    fn clock(&self, sequence: u64, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock { sequence, source }
    }

    fn execution(&self, sequence: u64, source: BoundaryError) -> Error {
        Error::Execution { sequence, source }
    }

    fn invalid_evidence(&self, sequence: u64, source: crate::evidence::Error) -> Error {
        Error::InvalidEvidence {
            sequence,
            message: WORKFLOW.describe_evidence(&source),
        }
    }

    fn stats_overflow(&self, sequence: u64, _source: StatsOverflow) -> Error {
        Error::StatisticsOverflow { sequence }
    }
}
