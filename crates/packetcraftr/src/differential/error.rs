// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::DeadlineExceeded;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error("invalid differential request field {field}: {message}")]
    InvalidRequest {
        field: &'static str,
        message: String,
    },
    #[error("differential timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error(
        "differential worst-case duration {actual:?} exceeds the configured limit of {limit:?}"
    )]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("differential live run requires a plan digest from a plan-only run")]
    PlanDigestMissing,
    #[error("differential plan digest mismatch: expected {expected}, presented {presented}")]
    PlanDigestMismatch { expected: String, presented: String },
    #[error("differential authorization failed")]
    Authorization(#[source] packetcraftr_core::error::BoundaryError),
    #[error("differential packet build failed")]
    Build(#[source] packetcraftr_core::error::BoundaryError),
    #[error("differential execution failed at attempt {attempt}")]
    Execution {
        attempt: u64,
        #[source]
        source: packetcraftr_core::error::BoundaryError,
    },
    #[error("differential capture evidence at attempt {attempt} is incomplete")]
    IncompleteEvidence { attempt: u64 },
    #[error("differential statistic accounting overflowed")]
    StatisticsOverflow,
    #[error("differential token generation failed: {message}")]
    TokenGeneration { message: String },
    #[error("differential responder I/O failed: {message}")]
    ResponderIo { message: String },
    #[error("differential progressive output failed")]
    Output {
        #[source]
        source: packetcraftr_core::error::BoundaryError,
    },
}

packetcraftr_core::deadline_error_conversions!(Error);

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(error) => error.classification(),
            Self::InvalidRequest { .. } | Self::InvalidTimeout { .. } => Classification::new(
                "cli.differential_limit",
                Kind::Usage,
                Some("use finite non-zero repeats, payload length, timeout, and duration limits"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.differential_resource_limit",
                Kind::Policy,
                Some("reduce repeats or timeout, or raise the campaign duration limit"),
            ),
            Self::PlanDigestMissing | Self::PlanDigestMismatch { .. } => Classification::new(
                "policy.differential_plan",
                Kind::Policy,
                Some("run the plan-only command first and present its digest to the live run"),
            ),
            Self::Authorization(error) | Self::Build(error) => error.classification(),
            Self::Execution { source, .. } | Self::Output { source } => source.classification(),
            Self::IncompleteEvidence { .. } => Classification::new(
                "capture.differential_incomplete",
                Kind::Io,
                Some("rerun with higher capture retention so a matched reply cannot be lost"),
            ),
            Self::StatisticsOverflow => Classification::new(
                "internal.differential_evidence",
                Kind::Internal,
                Some("treat the differential operation as incomplete"),
            ),
            Self::TokenGeneration { .. } | Self::ResponderIo { .. } => Classification::new(
                "io.differential",
                Kind::Io,
                Some("inspect the local socket or entropy source and retry"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(error) | Self::Output { source: error } => error.context(),
            _ => None,
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.as_causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.as_causes(),
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
