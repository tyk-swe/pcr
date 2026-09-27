// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::analysis::forwarding as analysis;
use packetcraftr_core::field::FieldValue;

use super::contract::Error;
use super::frame::{SourceFrame, Timestamp};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Sided<T> {
    pub ingress: T,
    pub egress: T,
}

published_enum! {
    pub enum Verdict from analysis::Verdict {
        Pass => "pass",
        Fail => "fail",
        Inconclusive => "inconclusive",
    }
}

published_enum! {
    pub enum Incomplete from analysis::Incomplete {
        Truncated => "truncated",
        FieldBudget => "field_budget",
    }
}

published_enum! {
    pub enum ValueState from analysis::ValueState {
        Observed => "observed",
        Absent => "absent",
        Truncated => "truncated",
        DecodeIncomplete => "decode_incomplete",
        FieldBudget => "field_budget",
    }
}

published_enum! {
    pub enum CheckKind from analysis::CheckKind {
        Preserve => "preserve",
        Expect => "expect",
        PreservePresence => "preserve_presence",
        ExpectAbsent => "expect_absent",
    }
}

published_enum! {
    pub enum Outcome from analysis::Outcome {
        Satisfied => "satisfied",
        Violated => "violated",
        Unevaluable => "unevaluable",
    }
}

published_enum! {
    pub enum ComparisonKind from analysis::ComparisonKind {
        CorrespondenceOnly => "correspondence_only",
        PropertyChecks => "property_checks",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub kind: CheckKind,
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl From<analysis::Check> for Check {
    fn from(value: analysis::Check) -> Self {
        Self {
            kind: value.kind.into(),
            field: value.field,
            value: value.value,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckEvaluation {
    pub check: Check,
    pub outcome: Outcome,
    pub expected_state: Option<ValueState>,
    pub actual_state: ValueState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<FieldValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<FieldValue>,
}

impl From<analysis::CheckEvaluation> for CheckEvaluation {
    fn from(value: analysis::CheckEvaluation) -> Self {
        Self {
            check: value.check.into(),
            outcome: value.outcome.into(),
            expected_state: value.expected_state.map(Into::into),
            actual_state: value.actual_state.into(),
            expected: value.expected,
            actual: value.actual,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleWarning {
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpectationRule {
    pub field: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestedRules {
    pub comparison: ComparisonKind,
    pub warnings: Vec<RuleWarning>,
    pub preserve_presence: Vec<String>,
    pub expect_absent: Vec<String>,
    pub identity: Vec<String>,
    pub preserve: Vec<String>,
    pub expect: Vec<ExpectationRule>,
}

impl From<analysis::RequestedRules> for RequestedRules {
    fn from(value: analysis::RequestedRules) -> Self {
        Self {
            comparison: value.comparison.into(),
            warnings: value
                .warnings
                .into_iter()
                .map(|warning| RuleWarning {
                    code: warning.code,
                    message: warning.message,
                })
                .collect(),
            preserve_presence: value.preserve_presence,
            expect_absent: value.expect_absent,
            identity: value.identity,
            preserve: value.preserve,
            expect: value
                .expect
                .into_iter()
                .map(|rule| ExpectationRule {
                    field: rule.field,
                    value: rule.value,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub unique_matches: u64,
    pub reordered_pairs: u64,
    pub ingress_only: u64,
    pub egress_only: u64,
    pub ambiguous_groups: u64,
    pub ambiguous_observations: u64,
    pub checks_evaluated: u64,
    pub checks_satisfied: u64,
    pub checks_violated: u64,
    pub checks_unevaluable: u64,
}

impl From<analysis::Summary> for Summary {
    fn from(value: analysis::Summary) -> Self {
        Self {
            unique_matches: value.unique_matches,
            reordered_pairs: value.reordered_pairs,
            ingress_only: value.ingress_only,
            egress_only: value.egress_only,
            ambiguous_groups: value.ambiguous_groups,
            ambiguous_observations: value.ambiguous_observations,
            checks_evaluated: value.checks_evaluated,
            checks_satisfied: value.checks_satisfied,
            checks_violated: value.checks_violated,
            checks_unevaluable: value.checks_unevaluable,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Omissions {
    pub matches: u64,
    pub violations: u64,
    pub unmatched_ingress: u64,
    pub unmatched_egress: u64,
    pub unkeyed_ingress: u64,
    pub unkeyed_egress: u64,
    pub ambiguous_groups: u64,
    pub group_members: u64,
}

impl From<analysis::Omissions> for Omissions {
    fn from(value: analysis::Omissions) -> Self {
        Self {
            matches: value.matches,
            violations: value.violations,
            unmatched_ingress: value.unmatched_ingress,
            unmatched_egress: value.unmatched_egress,
            unkeyed_ingress: value.unkeyed_ingress,
            unkeyed_egress: value.unkeyed_egress,
            ambiguous_groups: value.ambiguous_groups,
            group_members: value.group_members,
        }
    }
}

/// SHA-256 of the exact encoded source stream consumed through successful EOF.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureSource {
    pub sha256: String,
    pub encoded_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecodeContext {
    pub tls_ports: Vec<u16>,
    pub bindings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CaptureSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_filter: Option<String>,
    /// The input path as invoked; `-` for a capture read from stdin.
    pub path: String,
    pub read: u64,
    pub selected: u64,
    pub keyed: u64,
    pub unkeyed: u64,
    pub incomplete: u64,
}

/// A reference to one frame inside its own capture.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Evidence {
    pub frame: SourceFrame,
    /// The frame's capture timestamp, retained as per-capture evidence. It is
    /// never subtracted across captures and never labelled latency.
    pub timestamp: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    pub link_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<Incomplete>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<&'static str>,
}

impl TryFrom<&analysis::Evidence> for Evidence {
    type Error = Error;

    fn try_from(value: &analysis::Evidence) -> Result<Self, Self::Error> {
        Ok(Self {
            frame: SourceFrame::try_from(value.frame)?,
            timestamp: Timestamp::try_from(value.timestamp)?,
            interface: value.interface,
            link_type: value.link_type.0,
            incomplete: value.incomplete.map(Into::into),
            diagnostics: value.diagnostics.clone(),
        })
    }
}

fn evidence_list(values: &[analysis::Evidence]) -> Result<Vec<Evidence>, Error> {
    values.iter().map(Evidence::try_from).collect()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Match {
    pub key: Vec<FieldValue>,
    pub ingress: Evidence,
    pub egress: Evidence,
    /// Zero-based order among keyed observations of each capture.
    pub ingress_order: u64,
    pub egress_order: u64,
    pub reordered: bool,
    pub checks: Vec<CheckEvaluation>,
}

impl TryFrom<&analysis::Match> for Match {
    type Error = Error;

    fn try_from(value: &analysis::Match) -> Result<Self, Self::Error> {
        Ok(Self {
            key: value.key.clone(),
            ingress: Evidence::try_from(&value.ingress)?,
            egress: Evidence::try_from(&value.egress)?,
            ingress_order: value.ingress_order,
            egress_order: value.egress_order,
            reordered: value.reordered,
            checks: value.checks.iter().cloned().map(Into::into).collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    pub check: Check,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<FieldValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Evidence>,
    pub egress: Evidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<FieldValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<FieldValue>,
}

impl TryFrom<&analysis::Violation> for Violation {
    type Error = Error;

    fn try_from(value: &analysis::Violation) -> Result<Self, Self::Error> {
        Ok(Self {
            check: value.check.clone().into(),
            key: value.key.clone(),
            ingress: value.ingress.as_ref().map(Evidence::try_from).transpose()?,
            egress: Evidence::try_from(&value.egress)?,
            expected: value.expected.clone(),
            actual: value.actual.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Unkeyed {
    pub evidence: Evidence,
    pub key: Vec<Option<FieldValue>>,
}

impl TryFrom<&analysis::UnkeyedObservation> for Unkeyed {
    type Error = Error;

    fn try_from(value: &analysis::UnkeyedObservation) -> Result<Self, Self::Error> {
        Ok(Self {
            evidence: Evidence::try_from(&value.evidence)?,
            key: value.key.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AmbiguousGroup {
    pub key: Vec<FieldValue>,
    pub ingress: Vec<Evidence>,
    pub egress: Vec<Evidence>,
    /// True member counts; the listed evidence is bounded.
    pub ingress_total: u64,
    pub egress_total: u64,
    pub ingress_indistinguishable: bool,
    pub egress_indistinguishable: bool,
}

impl TryFrom<&analysis::AmbiguousGroup> for AmbiguousGroup {
    type Error = Error;

    fn try_from(value: &analysis::AmbiguousGroup) -> Result<Self, Self::Error> {
        Ok(Self {
            key: value.key.clone(),
            ingress: evidence_list(&value.ingress)?,
            egress: evidence_list(&value.egress)?,
            ingress_total: value.ingress_total,
            egress_total: value.egress_total,
            ingress_indistinguishable: value.ingress_indistinguishable,
            egress_indistinguishable: value.egress_indistinguishable,
        })
    }
}

impl From<(Vec<u16>, Vec<String>)> for DecodeContext {
    fn from((tls_ports, bindings): (Vec<u16>, Vec<String>)) -> Self {
        Self {
            tls_ports,
            bindings,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode: Option<DecodeContext>,
    pub verdict: Verdict,
    pub rules: RequestedRules,
    pub assumptions: &'static [&'static str],
    pub captures: Sided<Capture>,
    /// Counters computed over complete evidence before any detail bound.
    pub summary: Summary,
    pub matches: Vec<Match>,
    pub violations: Vec<Violation>,
    pub unmatched: Sided<Vec<Evidence>>,
    pub unkeyed: Sided<Vec<Unkeyed>>,
    pub ambiguous: Vec<AmbiguousGroup>,
    pub omitted: Omissions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub path: String,
    pub source: Option<CaptureSource>,
    pub selection_filter: Option<String>,
}

impl From<(&std::path::Path, Option<CaptureSource>, Option<&str>)> for Input {
    fn from(
        (path, source, selection_filter): (&std::path::Path, Option<CaptureSource>, Option<&str>),
    ) -> Self {
        Self {
            path: path.display().to_string(),
            source,
            selection_filter: selection_filter.map(str::to_owned),
        }
    }
}

fn capture(
    Input {
        path,
        source,
        selection_filter,
    }: Input,
    census: &analysis::SideSummary,
) -> Capture {
    Capture {
        source,
        selection_filter,
        path,
        read: census.read,
        selected: census.selected,
        keyed: census.keyed,
        unkeyed: census.unkeyed,
        incomplete: census.incomplete,
    }
}

fn unkeyed_list(values: &[analysis::UnkeyedObservation]) -> Result<Vec<Unkeyed>, Error> {
    values.iter().map(Unkeyed::try_from).collect()
}

impl
    TryFrom<(
        &analysis::Report,
        analysis::Sided<Input>,
        Option<DecodeContext>,
    )> for Report
{
    type Error = Error;

    fn try_from(
        (report, inputs, decode): (
            &analysis::Report,
            analysis::Sided<Input>,
            Option<DecodeContext>,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            decode,
            verdict: report.verdict.into(),
            rules: report.rules.clone().into(),
            assumptions: report.assumptions,
            captures: Sided {
                ingress: capture(inputs.ingress, &report.sides.ingress),
                egress: capture(inputs.egress, &report.sides.egress),
            },
            summary: report.summary.into(),
            matches: report
                .matches
                .iter()
                .map(Match::try_from)
                .collect::<Result<_, _>>()?,
            violations: report
                .violations
                .iter()
                .map(Violation::try_from)
                .collect::<Result<_, _>>()?,
            unmatched: Sided {
                ingress: evidence_list(&report.unmatched.ingress)?,
                egress: evidence_list(&report.unmatched.egress)?,
            },
            unkeyed: Sided {
                ingress: unkeyed_list(&report.unkeyed.ingress)?,
                egress: unkeyed_list(&report.unkeyed.egress)?,
            },
            ambiguous: report
                .ambiguous
                .iter()
                .map(AmbiguousGroup::try_from)
                .collect::<Result<_, _>>()?,
            omitted: report.omitted.into(),
        })
    }
}
