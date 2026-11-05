// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    budget::{DeadlineExceeded, Interrupted},
    error::BoundaryError,
};

/// Failures below workflow boundaries carry causes, never attempt/probe coordinates.
#[derive(Debug)]
pub(crate) enum Failure {
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    Authorization(BoundaryError),
    DurationLimit(DeadlineExceeded),
    Interrupted(Interrupted),
    Clock(Box<dyn std::error::Error + Send + Sync>),
    Execution(BoundaryError),
    InvalidEvidence(crate::evidence::error::Error),
    StatsOverflow(crate::StatsOverflow),
}

/// Maps a shared [`Failure`] onto a workflow whose `Error` has the common shape.
/// Expands where `Error` and `WORKFLOW` are in scope.
macro_rules! workflow_probe_error {
    () => {
        pub(crate) fn probe_error(sequence: u64, failure: crate::error::Failure) -> Error {
            match failure {
                crate::error::Failure::InvalidLimit {
                    field,
                    value,
                    reason,
                } => Error::InvalidLimit {
                    field,
                    value,
                    reason,
                },
                crate::error::Failure::Authorization(source) => Error::Authorization(source),
                crate::error::Failure::DurationLimit(source) => source.into(),
                crate::error::Failure::Interrupted(source) => source.into(),
                crate::error::Failure::Clock(source) => Error::Clock { sequence, source },
                crate::error::Failure::Execution(source) => Error::Execution { sequence, source },
                crate::error::Failure::InvalidEvidence(source) => Error::InvalidEvidence {
                    sequence,
                    message: WORKFLOW.describe_evidence(&source),
                },
                crate::error::Failure::StatsOverflow(_source) => {
                    Error::StatisticsOverflow { sequence }
                }
            }
        }
    };
}
pub(crate) use workflow_probe_error;
