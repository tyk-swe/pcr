// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::WORKFLOW;
use crate::StatsOverflow;
use crate::target::{Family, SelectionError};
use packetcraftr_core::error::BoundaryError;

/// Why a traceroute stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    TargetSelection(SelectionError),
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("invalid traceroute limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid traceroute destination port: {message}")]
    InvalidPort { message: String },
    #[error("invalid traceroute source port: must be non-zero and is only supported for UDP/TCP")]
    InvalidSourcePort,
    #[error("invalid traceroute probe option {option}: {reason}")]
    InvalidProbeOption {
        option: &'static str,
        reason: String,
    },
    #[error("traceroute timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("traceroute duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("invalid scan observation: {message}")]
    InvalidObservation { message: String },
    /// The evidence queues cannot retain what the plan's probes need.
    #[error("invalid traceroute collection")]
    Collection(#[source] BoundaryError),
    #[error("scoped link-local target {target} is not supported by this workflow")]
    ScopedTarget { target: String },
    #[error("traceroute authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("resolved target has no {family} address selected for this traceroute")]
    Family { family: &'static str },
    #[error("traceroute worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("traceroute execution failed at probe {sequence}")]
    Execution {
        sequence: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("traceroute rate clock failed before probe {sequence}")]
    Clock {
        sequence: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("traceroute executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("traceroute statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
    #[error("traceroute progressive output failed")]
    Output {
        #[source]
        source: BoundaryError,
    },
    #[error("traceroute events are incoherent: {message}")]
    IncoherentEvents { message: String },
}

packetcraftr_core::deadline_error_conversions!(Error);

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
            Self::InvalidObservation { .. }
            | Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidSourcePort
            | Self::InvalidProbeOption { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.traceroute_limit",
                Kind::Usage,
                Some(
                    "use finite non-zero hops, attempts, timeouts, rates, ports, evidence limits, and probe options valid for the strategy and address family",
                ),
            ),
            Self::Authorization(source)
            | Self::Collection(source)
            | Self::Execution { source, .. }
            | Self::Output { source } => source.classification(),
            Self::ScopedTarget { .. } => Classification::new(
                "capability.traceroute_scope",
                Kind::Capability,
                Some("use an unscoped destination or scan for scoped target support"),
            ),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some(
                    "select a traceroute address family returned by the authorized target resolution",
                ),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.traceroute_duration_limit",
                Kind::Policy,
                Some(
                    "reduce hops, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Clock { .. } => Classification::new(
                "io.traceroute_clock",
                Kind::Io,
                Some("inspect the traceroute timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.traceroute_evidence",
                Kind::Internal,
                Some("treat the trace as incomplete because executor evidence was inconsistent"),
            ),
            Self::IncoherentEvents { .. } => Classification::new(
                "internal.traceroute_event_coherence",
                Kind::Internal,
                Some(
                    "collect every traceroute event once, from one traceroute, in publication order",
                ),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(source) | Self::Output { source } => source.context(),
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
