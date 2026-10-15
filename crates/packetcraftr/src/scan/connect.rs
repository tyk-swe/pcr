// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod accounting;
mod attempts;
mod engine;
mod planning;
mod report;

use packetcraftr_core::error::BoundaryError;

use super::Error;
pub use report::{Aggregate, Collector, Endpoint, Event, Outcome, ProbeEvidence, Report, Stats};

fn invalid(field: &'static str, value: usize, reason: &str) -> Error {
    Error::InvalidLimit {
        field,
        value: value as u64,
        reason: reason.to_owned(),
    }
}

fn execution(
    sequence: u64,
    source: impl packetcraftr_core::error::Classified + Send + Sync + 'static,
) -> Error {
    Error::Execution {
        sequence,
        source: BoundaryError::from_error(source),
    }
}
