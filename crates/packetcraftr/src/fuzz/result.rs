// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::{diagnostic::Diagnostic, frame::Frame, fuzz as packet_fuzz};
use packetcraftr_netio::capture::Statistics as CaptureStatistics;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Built,
    Rejected,
    Response,
    Timeout,
}

impl CaseOutcome {
    /// The serialized name, for text output that must agree with JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Rejected => "rejected",
            Self::Response => "response",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub prepared: packet_fuzz::Case,
    pub outcome: CaseOutcome,
    pub sent: Option<Frame>,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
}

impl From<packet_fuzz::Case> for Case {
    fn from(prepared: packet_fuzz::Case) -> Self {
        let outcome = match prepared.outcome {
            packet_fuzz::CaseOutcome::Built => CaseOutcome::Built,
            packet_fuzz::CaseOutcome::Rejected => CaseOutcome::Rejected,
        };
        Self {
            prepared,
            outcome,
            sent: None,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct Result {
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<Case>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

/// Final live campaign metadata after every case event was published.
#[derive(Clone, Debug)]
pub struct Summary {
    pub seed: u64,
    pub first_case: u64,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn names_match_the_serialized_names() {
        for outcome in [
            CaseOutcome::Built,
            CaseOutcome::Rejected,
            CaseOutcome::Response,
            CaseOutcome::Timeout,
        ] {
            let serialized = serde_json::to_value(outcome).expect("case outcome is a name");
            assert_eq!(serialized.as_str(), Some(outcome.as_str()));
        }
    }
}
