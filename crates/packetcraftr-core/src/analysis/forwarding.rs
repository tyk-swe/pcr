// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline ingress/egress capture comparison.
//!
//! Two captures are read through the shared analysis pipeline independently,
//! each selected frame is reduced to an [`Observation`] — identity cells,
//! preserved-field cells, egress expectation outcomes, and evidence metadata —
//! and [`verify`] compares the two observation sets under explicit rules.
//!
//! The comparison is evidence, not device attribution: an unmatched ingress
//! observation says only that no selected egress observation carried its
//! declared identity, never that a device dropped it. Timestamps are retained
//! as per-capture evidence only; no clock relationship between the captures is
//! assumed and no cross-capture difference is labelled latency. No NAT
//! inference, tunnel reconstruction, stream reassembly, or fragment
//! correspondence is performed; identity keys must name packet content fields.
//!
//! Verdict semantics:
//!
//! - [`Verdict::Pass`]: every selected keyed ingress observation pairs uniquely
//!   with a keyed egress observation, every requested check evaluated with
//!   complete evidence and satisfied, and nothing was unkeyable, ambiguous,
//!   truncated, or budget-limited.
//! - [`Verdict::Fail`]: at least one attributable observation demonstrably
//!   violates an explicit preservation or expectation rule.
//! - [`Verdict::Inconclusive`]: missing, ambiguous, truncated, unkeyable, or
//!   budget-limited evidence prevents the requested conclusion. An empty
//!   selection is always inconclusive.

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

/// Which capture an observation belongs to. Capture identity is part of every
/// evidence reference: frame numbers are meaningful only within their own
/// capture, so frame 1 of the ingress capture is never frame 1 of the egress
/// capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// The capture taken before forwarding (the input under test).
    Ingress,
    /// The capture taken after forwarding (the output under test).
    Egress,
}
