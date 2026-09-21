// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Forwarding comparison reports and their evidence references.

use serde::Serialize;

use crate::field::FieldValue;
use crate::frame::{GlobalInterfaceId, LinkType};

use super::{Incomplete, Observation, Rules, ValueState};

/// Statements the report repeats verbatim so consumers never have to infer
/// the comparison's epistemic limits.
pub const ASSUMPTIONS: &[&str] = &[
    "identity is exact equality of the declared decoded field values; a field absent from an observation makes it unkeyable",
    "timestamps are per-capture evidence only; no clock relationship between the two captures is assumed, and no cross-capture difference is a latency measurement",
    "correspondence is observational evidence, not proof of device forwarding, loss, duplication, or reordering",
    "no NAT inference, tunnel reconstruction, stream reassembly, or fragment correspondence is performed",
    "ordinary value checks require readable values; two missing fields do not satisfy preservation",
    "presence and absence assertions describe the declared decoder view, not the absence of unknown wire protocols",
    "capture incompleteness does not erase a contradiction already established by readable fields",
];

/// The comparison result.
///
/// `fail` and `inconclusive` are deliberately distinct: `fail` requires an
/// attributable observation that demonstrably violates an explicit rule,
/// while `inconclusive` records that the evidence could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every selected keyed ingress observation paired uniquely, and every
    /// requested check evaluated with complete evidence and satisfied.
    Pass,
    /// An attributable observation demonstrably violates an explicit rule.
    Fail,
    /// Missing, ambiguous, truncated, unkeyable, or budget-limited evidence
    /// prevents the requested conclusion.
    Inconclusive,
}

/// A value the same on both captures — `ingress` belongs to the ingress
/// capture, `egress` to the egress capture, always.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Sided<T> {
    pub ingress: T,
    pub egress: T,
}

/// One capture's observation census, counted over its own frames only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SideSummary {
    /// Physical frames the capture reader yielded, selected or not. EOF is not
    /// evidence that no further frames existed.
    pub read: u64,
    /// Frames the selection kept.
    pub selected: u64,
    /// Selected frames whose declared identity resolved completely.
    pub keyed: u64,
    /// Selected frames missing at least one identity field.
    pub unkeyed: u64,
    /// Selected frames whose evidence is truncated or budget-limited.
    pub incomplete: u64,
}

/// One capture's contribution to the comparison: the collected observations
/// plus the physical frame count the run read.
#[derive(Clone, Debug, Default)]
pub struct SideInput {
    /// Physical frames read from this capture, including frames the selection
    /// excluded.
    pub frames_read: u64,
    /// Selected observations in capture order.
    pub observations: Vec<Observation>,
}

/// Aggregate comparison counters; every list in the report is a bounded
/// sample of what these counters measure exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Uniquely paired observations.
    pub unique_matches: u64,
    /// Uniquely paired observations whose egress order contradicts the
    /// ingress order of earlier pairs.
    pub reordered_pairs: u64,
    /// Keyed ingress observations with no keyed egress observation carrying
    /// their identity.
    pub ingress_only: u64,
    /// Keyed egress observations with no keyed ingress counterpart.
    pub egress_only: u64,
    /// Identity groups that are not 1:1.
    pub ambiguous_groups: u64,
    /// Observations inside ambiguous groups, both captures counted.
    pub ambiguous_observations: u64,
    /// Requested checks that produced a definite outcome.
    pub checks_evaluated: u64,
    /// Requested checks that held.
    pub checks_satisfied: u64,
    /// Requested checks demonstrably violated by an attributable observation.
    pub checks_violated: u64,
    /// Requested checks whose evidence was incomplete.
    pub checks_unevaluable: u64,
}

/// A reference to one frame inside its own capture. The `frame` number is
/// 1-based and capture-local; `interface` is the capture-global interface
/// identity when the source declared one.
#[derive(Clone, Debug, PartialEq)]
pub struct Evidence {
    pub frame: u64,
    pub timestamp: std::time::SystemTime,
    pub interface: Option<GlobalInterfaceId>,
    pub link_type: LinkType,
    /// Present when the capture evidence is incomplete.
    pub incomplete: Option<Incomplete>,
    /// Dissection diagnostic codes attached to this frame.
    pub diagnostics: Vec<&'static str>,
}

impl From<&Observation> for Evidence {
    fn from(observation: &Observation) -> Self {
        Self {
            frame: observation.frame,
            timestamp: observation.timestamp,
            interface: observation.interface,
            link_type: observation.link_type,
            incomplete: observation.incomplete,
            diagnostics: observation.diagnostics.clone(),
        }
    }
}

/// A selected observation whose identity could not fully resolve.
#[derive(Clone, Debug, PartialEq)]
pub struct UnkeyedObservation {
    pub evidence: Evidence,
    /// Identity cells in declared order; `None` marks the fields absent from
    /// the observation.
    pub key: Vec<Option<FieldValue>>,
}

/// Which kind of declared rule a check evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// `ingress.field` and `egress.field` must be equal.
    Preserve,
    /// `egress.field` must equal the declared literal.
    Expect,
    /// Explicitly compare presence in the declared decoder view.
    PreservePresence,
    /// Explicitly require absence in the declared decoder view.
    ExpectAbsent,
}

/// One rule echoed beside the outcome it produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub kind: CheckKind,
    pub field: String,
    /// The declared literal; present for `expect` checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// How one requested check resolved on one pair or observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The check evaluated and held.
    Satisfied,
    /// The check evaluated and was demonstrably violated.
    Violated,
    /// Incomplete evidence made the check unevaluable.
    Unevaluable,
}

/// One requested check applied to a uniquely matched pair.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckEvaluation {
    pub check: Check,
    pub outcome: Outcome,
    /// Per-cell evidence, unaffected by unrelated field-budget exhaustion.
    pub expected_state: Option<ValueState>,
    pub actual_state: ValueState,
    /// For `preserve`, the ingress observation's value; absent for `expect`,
    /// whose target is the declared literal on `check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<FieldValue>,
    /// The egress observation's value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<FieldValue>,
}

/// A uniquely matched observation pair.
#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    /// The identity cells both observations carried, in declared order.
    pub key: Vec<FieldValue>,
    pub ingress: Evidence,
    pub egress: Evidence,
    /// Zero-based order among keyed observations of each capture, so readers
    /// can see the sequence evidence a reordering flag rests on.
    pub ingress_order: u64,
    pub egress_order: u64,
    /// True when an earlier-ingress pair matched a later-egress observation.
    /// Order evidence only: not a claim about device behavior.
    pub reordered: bool,
    /// Per-requested-check outcomes in declaration order (preservations,
    /// then expectations).
    pub checks: Vec<CheckEvaluation>,
}

/// A demonstrably violated check attributed to concrete observations.
#[derive(Clone, Debug, PartialEq)]
pub struct Violation {
    pub check: Check,
    /// The shared identity; absent when the violating egress observation was
    /// unkeyed.
    pub key: Option<Vec<FieldValue>>,
    /// The matched ingress observation, when the pair was unique.
    pub ingress: Option<Evidence>,
    pub egress: Evidence,
    /// For `preserve`, the ingress value that did not survive. For `expect`,
    /// the declared literal lives on `check`.
    pub expected: Option<FieldValue>,
    /// The egress observation's offending value.
    pub actual: Option<FieldValue>,
}

/// An identity carried by more than one observation on at least one side.
///
/// Members are listed in capture order and never paired; when every member's
/// projected evidence is identical under the requested rules, the group is
/// marked indistinguishable.
#[derive(Clone, Debug, PartialEq)]
pub struct AmbiguousGroup {
    pub key: Vec<FieldValue>,
    pub ingress: Vec<Evidence>,
    pub egress: Vec<Evidence>,
    /// True member counts; the listed evidence is bounded.
    pub ingress_total: u64,
    pub egress_total: u64,
    /// Members indistinguishable under the requested non-identity fields.
    pub ingress_indistinguishable: bool,
    pub egress_indistinguishable: bool,
}

/// How many report entries each detail ceiling dropped, per category.
///
/// The counters in [`Summary`] always reflect complete evidence; an omission
/// means the document lists fewer rows than were analyzed, never that the
/// analysis was incomplete.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Omissions {
    pub matches: u64,
    pub violations: u64,
    pub unmatched_ingress: u64,
    pub unmatched_egress: u64,
    pub unkeyed_ingress: u64,
    pub unkeyed_egress: u64,
    pub ambiguous_groups: u64,
    /// Group members kept out of listed evidence; `*_total` still counts them.
    pub group_members: u64,
}

/// The complete comparison result.
#[derive(Clone, Debug)]
pub struct Report {
    pub verdict: Verdict,
    /// The rules exactly as declared, so the report stands alone.
    pub rules: RequestedRules,
    pub assumptions: &'static [&'static str],
    pub sides: Sided<SideSummary>,
    pub summary: Summary,
    pub matches: Vec<Match>,
    pub violations: Vec<Violation>,
    /// Keyed observations with no counterpart.
    pub unmatched: Sided<Vec<Evidence>>,
    /// Selected observations without a complete identity.
    pub unkeyed: Sided<Vec<UnkeyedObservation>>,
    pub ambiguous: Vec<AmbiguousGroup>,
    pub omitted: Omissions,
}

/// The declared rules, echoed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestedRules {
    pub comparison: ComparisonKind,
    pub warnings: Vec<RuleWarning>,
    pub preserve_presence: Vec<String>,
    pub expect_absent: Vec<String>,
    /// Identity fields in declared order.
    pub identity: Vec<String>,
    /// Fields that must compare equal on a matched pair.
    pub preserve: Vec<String>,
    /// Declared egress expectations.
    pub expect: Vec<ExpectationRule>,
}

/// The scope of a pass: correspondence alone or explicitly requested properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonKind {
    CorrespondenceOnly,
    PropertyChecks,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleWarning {
    pub code: &'static str,
    pub message: String,
}

impl RequestedRules {
    pub(super) fn from_rules(rules: &Rules) -> Self {
        let correspondence_only = rules.preserve.is_empty() && rules.expectations.is_empty();
        let mut warnings = Vec::new();
        if correspondence_only {
            warnings.push(RuleWarning {
                code: "verify.correspondence_only",
                message: "pass establishes exact unique correspondence only; no property assertions were requested".to_owned(),
            });
        }
        let overlap: Vec<_> = rules
            .preserve_fields()
            .iter()
            .filter(|field| rules.identity_fields().contains(field))
            .cloned()
            .collect();
        if !overlap.is_empty() {
            warnings.push(RuleWarning {
                code: "verify.identity_preservation_overlap",
                message: format!("identity also contains {}; changes to these fields prevent matching instead of establishing a preservation violation", overlap.join(", ")),
            });
        }
        Self {
            comparison: if correspondence_only {
                ComparisonKind::CorrespondenceOnly
            } else {
                ComparisonKind::PropertyChecks
            },
            warnings,
            identity: rules.identity_fields().to_vec(),
            preserve: rules.preserve_fields().to_vec(),
            preserve_presence: rules.preserve_presence_fields().to_vec(),
            expect_absent: rules.absent_fields().map(str::to_owned).collect(),
            expect: rules
                .expectation_specs()
                .map(|(field, value)| ExpectationRule {
                    field: field.to_owned(),
                    value: value.to_owned(),
                })
                .collect(),
        }
    }
}

/// One `FIELD=VALUE` expectation as declared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpectationRule {
    pub field: String,
    pub value: String,
}
