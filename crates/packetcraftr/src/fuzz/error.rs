// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;
use packetcraftr_core::error::{Classification, Classified, Context};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
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
    #[error("fuzz rate clock failed before case {case_index}: {message}")]
    Clock { case_index: u64, message: String },
    #[error("fuzz executor returned invalid evidence at case {case_index}: {message}")]
    InvalidEvidence { case_index: u64, message: String },
    #[error("fuzz statistic accounting overflowed at case {case_index}")]
    StatisticsOverflow { case_index: u64 },
    #[error("fuzz progressive output failed: {source}")]
    Output {
        #[source]
        source: crate::BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Campaign(error) => error.classification(),
            Self::InvalidLimit { .. } | Self::InvalidTimeout { .. } => Classification::new(
                "cli.fuzz_limit",
                Some("use finite non-zero rate, timeout, evidence, and duration limits"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.fuzz_resource_limit",
                Some("reduce cases, packet sizes, timeout, or rate delay"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.fuzz_clock",
                Some("inspect the fuzz rate timer and account for cases already transmitted"),
            ),
            Self::Output { source } => source.classification(),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.fuzz_evidence",
                Some("treat the fuzz operation as incomplete because evidence was inconsistent"),
            ),
        }
    }

    fn context(&self) -> Context {
        match self {
            Self::Campaign(error) => error.context(),
            Self::Authorization(error) | Self::Output { source: error } => error.context(),
            Self::Execution { case_index, .. }
            | Self::Clock { case_index, .. }
            | Self::InvalidEvidence { case_index, .. }
            | Self::StatisticsOverflow { case_index } => Context::case_index(*case_index),
            _ => Context::default(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Campaign(error) => error.causes(),
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.causes(),
            _ => Vec::new(),
        }
    }
}

pub(super) fn duration_limit(error: DeadlineExceeded) -> Error {
    Error::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}
