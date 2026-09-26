// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use super::WORKFLOW;
use crate::execution::ExchangeEvidenceError;
use crate::target::Family;
use crate::{BoundaryError, StatsOverflow};

/// Why a traceroute stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("traceroute: {0}")]
    Cancelled(#[source] Cancelled),
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
    #[error("traceroute timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("traceroute duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("traceroute authorization failed: {0}")]
    Authorization(#[source] BoundaryError),
    #[error("resolved target has no {family} address selected for this traceroute")]
    Family { family: &'static str },
    #[error("traceroute worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("traceroute execution failed at probe {sequence}: {source}")]
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
    #[error("traceroute progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
    /// A collector saw events that disagree with the report.
    #[error("traceroute events are incoherent: {message}")]
    IncoherentEvents { message: String },
}

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
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidSourcePort
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.traceroute_limit",
                Kind::Usage,
                Some(
                    "use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits",
                ),
            ),
            Self::Authorization(source)
            | Self::Execution { source, .. }
            | Self::Output { source } => source.classification(),
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

    /// Boundary-sourced variants delegate because a [`BoundaryError`] carries
    /// a captured `causes` snapshot its own source chain no longer holds.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(source)
            | Self::Execution { source, .. }
            | Self::Output { source } => source.causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }
}

/// Names shared admission and execution failures as traceroute errors at the probe
/// sequence of the batch they concern.
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
        Error::DurationLimit {
            actual: source.actual,
            limit: source.limit,
        }
    }

    fn interrupted(&self, sequence: u64, source: Interrupted) -> Error {
        match source {
            Interrupted::Exceeded(source) => self.duration_limit(sequence, source),
            Interrupted::Cancelled(source) => Error::Cancelled(source),
            _ => Error::Cancelled(Cancelled),
        }
    }

    fn clock(&self, sequence: u64, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock { sequence, source }
    }

    fn execution(&self, sequence: u64, source: BoundaryError) -> Error {
        Error::Execution { sequence, source }
    }

    fn invalid_evidence(&self, sequence: u64, source: ExchangeEvidenceError) -> Error {
        Error::InvalidEvidence {
            sequence,
            message: WORKFLOW.describe_evidence(&source),
        }
    }

    fn stats_overflow(&self, sequence: u64, _source: StatsOverflow) -> Error {
        Error::StatisticsOverflow { sequence }
    }
}
