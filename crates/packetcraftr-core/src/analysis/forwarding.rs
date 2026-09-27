// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline ingress/egress capture comparison.

mod error;
mod evaluate;
mod limits;
mod observation;
mod report;
mod rules;

pub use error::Error;
pub use evaluate::{SideInput, verify, verify_with_limits};
pub use limits::Limits;
pub use observation::{Collector, ExpectationOutcome, Incomplete, Observation, ValueState};
pub use report::{
    ASSUMPTIONS, AmbiguousGroup, Check, CheckEvaluation, CheckKind, ComparisonKind, Evidence,
    ExpectationRule, Match, Omissions, Outcome, Report, RequestedRules, RuleWarning, SideSummary,
    Sided, Summary, UnkeyedObservation, Verdict, Violation,
};
pub use rules::{Declarations, Expectation, Rules};

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Ingress,
    Egress,
}
