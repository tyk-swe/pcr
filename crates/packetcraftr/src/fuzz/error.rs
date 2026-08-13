// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;
use packetcraftr_core::error::{Classification, Classified, Kind};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FuzzError {
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
    #[error("permissive or malformed fuzz cases require an explicit live opt-in")]
    MalformedLiveOptInRequired,
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
    #[error("fuzz rate clock failed before case {case_index}: {message}")]
    Clock { case_index: u64, message: String },
    #[error("fuzz executor returned invalid evidence at case {case_index}: {message}")]
    InvalidEvidence { case_index: u64, message: String },
    #[error("fuzz statistic accounting overflowed at case {case_index}")]
    StatisticsOverflow { case_index: u64 },
}

impl FuzzError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { case_index, .. }
            | Self::Clock { case_index, .. }
            | Self::InvalidEvidence { case_index, .. }
            | Self::StatisticsOverflow { case_index } => Some(*case_index),
            Self::Campaign(_)
            | Self::InvalidLimit { .. }
            | Self::InvalidTimeout { .. }
            | Self::MalformedLiveOptInRequired
            | Self::DurationLimit { .. }
            | Self::Authorization(_) => None,
        }
    }
}

impl Classified for FuzzError {
    fn classification(&self) -> Classification {
        match self {
            Self::Campaign(error) => error.classification(),
            Self::InvalidLimit { .. } | Self::InvalidTimeout { .. } => Classification::new(
                "cli.fuzz_limit",
                Kind::Cli,
                Some("use finite non-zero rate, timeout, evidence, and duration limits"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.fuzz_resource_limit",
                Kind::Policy,
                Some("reduce cases, packet sizes, timeout, or rate delay"),
            ),
            Self::MalformedLiveOptInRequired => Classification::new(
                "policy.fuzz_malformed_opt_in",
                Kind::Policy,
                Some("pass the explicit malformed-live opt-in and authorize permissive packets"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.fuzz_clock",
                Kind::Io,
                Some("inspect the fuzz rate timer and account for cases already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.fuzz_evidence",
                Kind::Internal,
                Some("treat the fuzz operation as incomplete because evidence was inconsistent"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Campaign(error) => error.causes(),
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

pub(super) fn duration_limit(error: DeadlineExceeded) -> FuzzError {
    FuzzError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}
