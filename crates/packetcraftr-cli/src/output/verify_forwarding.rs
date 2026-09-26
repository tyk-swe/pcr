// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Forwarding output with capture-local numbering and per-capture evidence.
//! Uses shared timestamps/source references and makes no claims about device
//! behavior.

use serde::Serialize;

use packetcraftr_core::analysis::forwarding as analysis;
use packetcraftr_core::field::FieldValue;

use super::contract::Error;
use super::frame::{SourceFrame, Timestamp};

/// A value the same on both captures: `ingress` belongs to the ingress
/// capture, `egress` to the egress capture, always.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Sided<T> {
    pub ingress: T,
    pub egress: T,
}

published_enum! {
    /// The comparison result.
    pub enum Verdict from analysis::Verdict {
        Pass => "pass",
        Fail => "fail",
        Inconclusive => "inconclusive",
    }
}

published_enum! {
    /// Why an observation's evidence is incomplete.
    pub enum Incomplete from analysis::Incomplete {
        Truncated => "truncated",
        FieldBudget => "field_budget",
    }
}

published_enum! {
    /// What one projected cell establishes.
    pub enum ValueState from analysis::ValueState {
        Observed => "observed",
        Absent => "absent",
        Truncated => "truncated",
        DecodeIncomplete => "decode_incomplete",
        FieldBudget => "field_budget",
    }
}

published_enum! {
    /// The kind of property a check asserts.
    pub enum CheckKind from analysis::CheckKind {
        Preserve => "preserve",
        Expect => "expect",
        PreservePresence => "preserve_presence",
        ExpectAbsent => "expect_absent",
    }
}

published_enum! {
    /// How one requested check resolved.
    pub enum Outcome from analysis::Outcome {
        Satisfied => "satisfied",
        Violated => "violated",
        Unevaluable => "unevaluable",
    }
}

published_enum! {
    /// The scope of a pass: correspondence alone or requested properties.
    pub enum ComparisonKind from analysis::ComparisonKind {
        CorrespondenceOnly => "correspondence_only",
        PropertyChecks => "property_checks",
    }
}

/// One rule echoed beside the outcome it produced.
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

/// One requested check applied to a uniquely matched pair.
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

/// A warning about what the declared rules can establish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleWarning {
    pub code: &'static str,
    pub message: String,
}

/// One `FIELD=VALUE` expectation as declared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpectationRule {
    pub field: String,
    pub value: String,
}

/// The rules exactly as declared, so the report stands alone.
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

/// Aggregate comparison counters over complete evidence.
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

/// How many report entries each detail ceiling dropped, per category.
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

/// SHA-256 of the exact encoded source stream consumed through successful
/// EOF. It binds a completed report to bytes, not merely a mutable pathname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureSource {
    pub sha256: String,
    pub encoded_bytes: u64,
}

/// Decoder overrides are part of the interpretation, not acquisition facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecodeContext {
    pub tls_ports: Vec<u16>,
    pub bindings: Vec<String>,
}

/// One capture's place in the comparison: the path it was read from plus its
/// observation census, counted over its own frames only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CaptureSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_filter: Option<String>,
    /// The input path as invoked; `-` for a capture read from stdin.
    pub path: String,
    /// Physical frames the capture reader yielded, selected or not.
    pub read: u64,
    /// Frames the side's selection kept.
    pub selected: u64,
    /// Selected frames whose declared identity resolved completely.
    pub keyed: u64,
    /// Selected frames missing at least one identity field.
    pub unkeyed: u64,
    /// Selected frames whose evidence was truncated or budget-limited.
    pub incomplete: u64,
}

/// A reference to one frame inside its own capture.
///
/// `frame` is the capture-local 1-based physical frame number: frame 1 of the
/// ingress capture is never frame 1 of the egress capture.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Evidence {
    pub frame: SourceFrame,
    /// The frame's capture timestamp, retained as per-capture evidence. It is
    /// never subtracted across captures and never labelled latency.
    pub timestamp: Timestamp,
    /// The capture-global interface identity, when the source declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    pub link_type: u32,
    /// Present when the observation's evidence was truncated by the capture
    /// snap length or limited by the field-projection budget.
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

/// A uniquely matched observation pair, listed in ingress observation order.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Match {
    /// The identity cells both observations carried, in declared order.
    pub key: Vec<FieldValue>,
    pub ingress: Evidence,
    pub egress: Evidence,
    /// Zero-based order among keyed observations of each capture.
    pub ingress_order: u64,
    pub egress_order: u64,
    /// True when an earlier-ingress pair matched a later-egress observation;
    /// order evidence only, not a claim about device behavior.
    pub reordered: bool,
    /// Per-requested-check outcomes in declaration order.
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

/// A demonstrably violated check attributed to concrete observations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    pub check: Check,
    /// The shared identity; absent when the violating egress observation was
    /// unkeyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<FieldValue>>,
    /// The matched ingress observation, when the pair was unique.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Evidence>,
    pub egress: Evidence,
    /// For `preserve`, the ingress value that did not survive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<FieldValue>,
    /// The egress observation's offending value.
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

/// A selected observation whose identity could not fully resolve.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Unkeyed {
    pub evidence: Evidence,
    /// Identity cells in declared order; null marks the absent fields.
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

/// An identity carried by more than one observation on at least one side.
/// Members are listed in capture order and never paired.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AmbiguousGroup {
    pub key: Vec<FieldValue>,
    pub ingress: Vec<Evidence>,
    pub egress: Vec<Evidence>,
    /// True member counts; the listed evidence is bounded.
    pub ingress_total: u64,
    pub egress_total: u64,
    /// Members indistinguishable under the requested non-identity rules.
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

/// Decoder overrides the comparison ran under.
impl From<(Vec<u16>, Vec<String>)> for DecodeContext {
    fn from((tls_ports, bindings): (Vec<u16>, Vec<String>)) -> Self {
        Self {
            tls_ports,
            bindings,
        }
    }
}

/// The complete comparison result; the aggregate `result` and the NDJSON
/// terminal `complete` record carry the same document.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode: Option<DecodeContext>,
    pub verdict: Verdict,
    /// The rules exactly as declared, so the report stands alone.
    pub rules: RequestedRules,
    /// The epistemic limits the comparison ran under, repeated verbatim.
    pub assumptions: &'static [&'static str],
    /// Per-capture censuses; each side's counts cover its own frames only.
    pub captures: Sided<Capture>,
    /// Counters computed over complete evidence before any detail bound.
    pub summary: Summary,
    /// Uniquely paired observations, in ingress observation order.
    pub matches: Vec<Match>,
    pub violations: Vec<Violation>,
    /// Keyed observations with no keyed counterpart on the other side. An
    /// unmatched ingress observation is not evidence of device loss; an
    /// unmatched egress observation is not evidence of duplication.
    pub unmatched: Sided<Vec<Evidence>>,
    /// Selected observations without a complete identity.
    pub unkeyed: Sided<Vec<Unkeyed>>,
    /// Identity groups that are not 1:1; members are never paired.
    pub ambiguous: Vec<AmbiguousGroup>,
    /// Per-category counts of detail entries the `--max-details` bound kept
    /// out of this document.
    pub omitted: Omissions,
}

/// One capture as invoked: its path, the digest of the stream the comparison
/// consumed, and its selection filter.
pub type Input = (String, Option<CaptureSource>, Option<String>);

fn capture((path, source, selection_filter): Input, census: &analysis::SideSummary) -> Capture {
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

/// The core comparison, with each capture as invoked and the decoder
/// overrides, in the shared output timestamp and source-frame forms.
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
