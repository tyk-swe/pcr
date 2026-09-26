// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::{DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(transparent)]
    Campaign(#[from] packetcraftr_core::fuzz::Error),
    #[error("invalid fuzz limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("fuzz live timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("fuzz worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("fuzz authorization failed: {0}")]
    Authorization(#[from] crate::BoundaryError),
    #[error("fuzz execution failed at case {case_index}: {source}")]
    Execution {
        case_index: u64,
        #[source]
        source: crate::BoundaryError,
    },
    #[error("fuzz rate clock failed before case {case_index}")]
    Clock {
        case_index: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("fuzz executor returned invalid evidence at case {case_index}: {message}")]
    InvalidEvidence { case_index: u64, message: String },
    /// The case's exact bytes could not be prepared on the route the executor
    /// reported, so its transmission cannot be verified.
    #[error("fuzz executor returned invalid evidence at case {case_index}: {source}")]
    UnverifiableRoute {
        case_index: u64,
        #[source]
        source: crate::Error,
    },
    #[error("fuzz statistic accounting overflowed at case {case_index}")]
    StatisticsOverflow { case_index: u64 },
    #[error("fuzz progressive output failed: {source}")]
    Output {
        #[source]
        source: crate::BoundaryError,
    },
}

packetcraftr_core::deadline_error_conversions!(Error);

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(error) => error.classification(),
            Self::Campaign(error) => error.classification(),
            Self::InvalidLimit { .. } | Self::InvalidTimeout { .. } => Classification::new(
                "cli.fuzz_limit",
                Kind::Usage,
                Some("use finite non-zero rate, timeout, evidence, and duration limits"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.fuzz_resource_limit",
                Kind::Policy,
                Some("reduce cases, packet sizes, timeout, or rate delay"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Execution { source, .. } | Self::Output { source } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.fuzz_clock",
                Kind::Io,
                Some("inspect the fuzz rate timer and account for cases already transmitted"),
            ),
            Self::InvalidEvidence { .. }
            | Self::UnverifiableRoute { .. }
            | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.fuzz_evidence",
                Kind::Internal,
                Some("treat the fuzz operation as incomplete because evidence was inconsistent"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Campaign(error) => error.context(),
            Self::Authorization(error) | Self::Output { source: error } => error.context(),
            Self::Execution { case_index, .. }
            | Self::Clock { case_index, .. }
            | Self::InvalidEvidence { case_index, .. }
            | Self::UnverifiableRoute { case_index, .. }
            | Self::StatisticsOverflow { case_index } => Some(Coordinate::CaseIndex(*case_index)),
            _ => None,
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    /// The boundary-sourced variants delegate instead: a [`BoundaryError`]
    /// carries a captured `causes` snapshot its own source chain no longer
    /// holds.
    ///
    /// [`BoundaryError`]: crate::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Campaign(error) => error.causes(),
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

pub(super) fn duration_limit(error: DeadlineExceeded) -> Error {
    Error::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}

/// Names execution-context failures at the index of the case they concern.
#[derive(Clone, Copy, Debug)]
pub(super) struct CaseErrors;

impl crate::execution::PacingErrors for CaseErrors {
    type Error = Error;
    type Step = u64;

    fn duration_limit(&self, _case_index: u64, source: DeadlineExceeded) -> Error {
        duration_limit(source)
    }

    fn interrupted(&self, _case_index: u64, source: Interrupted) -> Error {
        source.into_error()
    }

    fn clock(&self, case_index: u64, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock { case_index, source }
    }
}

impl crate::execution::Errors for CaseErrors {
    fn execution(&self, case_index: u64, source: crate::BoundaryError) -> Error {
        Error::Execution { case_index, source }
    }

    fn invalid_evidence(&self, case_index: u64, message: String) -> Error {
        Error::InvalidEvidence {
            case_index,
            message,
        }
    }

    fn stats_overflow(&self, case_index: u64, _source: crate::StatsOverflow) -> Error {
        Error::StatisticsOverflow { case_index }
    }
}
