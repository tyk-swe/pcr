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

/// A workflow error that can absorb a shared [`Failure`] at a probe coordinate.
pub(crate) trait FromFailure: Sized {
    fn from_failure(sequence: u64, failure: Failure) -> Self;
}

macro_rules! impl_from_failure {
    (
        $error:ty,
        $step:ident,
        invalid_limit: |$field:ident, $value:ident, $reason:ident| $invalid_limit:expr,
        duration_limit: |$dur:ident| $duration_limit:expr,
        interrupted: |$int:ident| $interrupted:expr,
        clock: |$clock:ident| $clock_arm:expr,
        execution: |$exec:ident| $exec_arm:expr,
        invalid_evidence: |$ev:ident| $ev_arm:expr,
        stats_overflow: |$ovf:ident| $ovf_arm:expr $(,)?
    ) => {
        impl $crate::error::FromFailure for $error {
            fn from_failure($step: u64, failure: $crate::error::Failure) -> Self {
                match failure {
                    $crate::error::Failure::InvalidLimit {
                        field: $field,
                        value: $value,
                        reason: $reason,
                    } => $invalid_limit,
                    $crate::error::Failure::Authorization(source) => Self::Authorization(source),
                    $crate::error::Failure::DurationLimit($dur) => $duration_limit,
                    $crate::error::Failure::Interrupted($int) => $interrupted,
                    $crate::error::Failure::Clock($clock) => $clock_arm,
                    $crate::error::Failure::Execution($exec) => $exec_arm,
                    $crate::error::Failure::InvalidEvidence($ev) => $ev_arm,
                    $crate::error::Failure::StatsOverflow($ovf) => $ovf_arm,
                }
            }
        }
    };
    ($error:ty, workflow: $workflow:expr) => {
        $crate::error::impl_from_failure!(
            $error,
            sequence,
            invalid_limit: |field, value, reason| Self::InvalidLimit {
                field,
                value,
                reason,
            },
            duration_limit: |source| source.into(),
            interrupted: |source| source.into(),
            clock: |source| Self::Clock { sequence, source },
            execution: |source| Self::Execution { sequence, source },
            invalid_evidence: |source| Self::InvalidEvidence {
                sequence,
                message: $workflow.describe_evidence(&source),
            },
            stats_overflow: |_source| Self::StatisticsOverflow { sequence },
        );
    };
}

pub(crate) use impl_from_failure;
