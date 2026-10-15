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
    InvalidEvidence(crate::evidence::Error),
    StatsOverflow(crate::StatsOverflow),
}
