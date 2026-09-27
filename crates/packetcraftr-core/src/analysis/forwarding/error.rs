// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The comparison's failure type and its classification.

use crate::budget::Cancelled;
use crate::error::{Classification, Classified, Kind};

use super::Side;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Projection(crate::filter::Error),
    #[error(transparent)]
    Filter(#[from] crate::filter::Error),
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    /// The field describes a position inside one capture, so it cannot serve
    /// as cross-capture identity or a preservation rule.
    #[error(
        "{role} field {field:?} is {why}; rules must name packet fields, not per-capture positions"
    )]
    CaptureLocal {
        role: &'static str,
        field: String,
        why: &'static str,
    },
    #[error("invalid expectation {rule:?}: expected FIELD=VALUE")]
    ExpectationSeparator { rule: String },
    #[error("invalid expectation {rule:?}: expected FIELD=VALUE with non-empty sides")]
    ExpectationEmptySide { rule: String },
    #[error("invalid expectation {rule:?}")]
    Expectation {
        rule: String,
        #[source]
        source: crate::filter::Error,
    },
    #[error("invalid expectation {rule:?}")]
    ExpectationField {
        rule: String,
        #[source]
        source: crate::filter::Error,
    },
    /// The retained-evidence budget was exhausted; nothing was evicted.
    #[error("retained observation evidence exceeds the {limit} byte budget")]
    EvidenceBudget { limit: usize },
    #[error("verification declarations exceed 256 rules or 65536 source bytes")]
    RuleBudget,
    #[error(
        "observation {frame} on {side:?} was not collected in order under these compiled rules"
    )]
    ObservationContract { side: Side, frame: u64 },
    #[error("comparison scratch charge exceeds the {limit} byte budget")]
    ScratchBudget { limit: usize },
    #[error(transparent)]
    Interrupted(#[from] crate::budget::Interrupted),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Projection(source) | Self::ExpectationField { source, .. } => {
                source.classification()
            }
            Self::Filter(source) | Self::Expectation { source, .. } => source.classification(),
            Self::Cancelled(source) => source.classification(),
            Self::Interrupted(source) => source.classification(),
            Self::ObservationContract { .. } => Classification::new(
                "analysis.verify_observation_contract",
                Kind::Usage,
                Some("collect both sides, in capture order, with the same compiled Rules instance"),
            ),
            Self::ScratchBudget { .. } => Classification::new(
                "policy.verify_scratch_limit",
                Kind::Policy,
                Some("reduce input or raise the finite comparison scratch budget"),
            ),
            Self::CaptureLocal { .. }
            | Self::ExpectationSeparator { .. }
            | Self::ExpectationEmptySide { .. }
            | Self::RuleBudget => Classification::new(
                "cli.verify_rule",
                Kind::Usage,
                Some("declare identity, preservation, and expectation rules over packet fields"),
            ),
            Self::EvidenceBudget { .. } => Classification::new(
                "policy.verify_evidence_limit",
                Kind::Policy,
                Some("reduce the selected frames or raise the finite --max-evidence-bytes budget"),
            ),
        }
    }
}
