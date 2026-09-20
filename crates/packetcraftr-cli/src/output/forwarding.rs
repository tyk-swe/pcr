// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured `verify-forwarding` comparison output.
//!
//! The wire model keeps the core report's semantics — capture-local frame
//! numbers, per-capture evidence, and a verdict that never claims device
//! behavior — while converting timestamps and source references into the
//! shared output representations.

use serde::Serialize;

use packetcraftr_core::analysis::forwarding as analysis;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::LinkType;

use super::contract::Error;
use super::frame::{SourceFrame, Timestamp};

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
    /// The capture record's link-layer type.
    pub link_type: LinkType,
    /// Present when the observation's evidence was truncated by the capture
    /// snap length or limited by the field-projection budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<analysis::Incomplete>,
    /// Dissection diagnostic codes the decoder attached to this frame.
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
            link_type: value.link_type,
            incomplete: value.incomplete,
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
    pub checks: Vec<analysis::CheckEvaluation>,
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
            checks: value.checks.clone(),
        })
    }
}

/// A demonstrably violated check attributed to concrete observations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    pub check: analysis::Check,
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
            check: value.check.clone(),
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

/// The complete comparison result; the aggregate `result` and the NDJSON
/// terminal `complete` record carry the same document.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode: Option<DecodeContext>,
    pub verdict: analysis::Verdict,
    /// The rules exactly as declared, so the report stands alone.
    pub rules: analysis::RequestedRules,
    /// The epistemic limits the comparison ran under, repeated verbatim.
    pub assumptions: &'static [&'static str],
    /// Per-capture censuses; each side's counts cover its own frames only.
    pub captures: analysis::Sided<Capture>,
    /// Counters computed over complete evidence before any detail bound.
    pub summary: analysis::Summary,
    /// Uniquely paired observations, in ingress observation order.
    pub matches: Vec<Match>,
    /// Attributable rule violations, each carrying the offending value.
    pub violations: Vec<Violation>,
    /// Keyed observations with no keyed counterpart on the other side. An
    /// unmatched ingress observation is not evidence of device loss; an
    /// unmatched egress observation is not evidence of duplication.
    pub unmatched: analysis::Sided<Vec<Evidence>>,
    /// Selected observations without a complete identity.
    pub unkeyed: analysis::Sided<Vec<Unkeyed>>,
    /// Identity groups that are not 1:1; members are never paired.
    pub ambiguous: Vec<AmbiguousGroup>,
    /// Per-category counts of detail entries the `--max-details` bound kept
    /// out of this document.
    pub omitted: analysis::Omissions,
}

impl Report {
    /// Converts the core report, attaching the invoked input paths and the
    /// shared output timestamp/source-frame representations.
    pub fn from_report(
        report: &analysis::Report,
        paths: analysis::Sided<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            decode: None,
            verdict: report.verdict,
            rules: report.rules.clone(),
            assumptions: report.assumptions,
            captures: analysis::Sided {
                ingress: Capture {
                    source: None,
                    selection_filter: None,
                    path: paths.ingress,
                    read: report.sides.ingress.read,
                    selected: report.sides.ingress.selected,
                    keyed: report.sides.ingress.keyed,
                    unkeyed: report.sides.ingress.unkeyed,
                    incomplete: report.sides.ingress.incomplete,
                },
                egress: Capture {
                    source: None,
                    selection_filter: None,
                    path: paths.egress,
                    read: report.sides.egress.read,
                    selected: report.sides.egress.selected,
                    keyed: report.sides.egress.keyed,
                    unkeyed: report.sides.egress.unkeyed,
                    incomplete: report.sides.egress.incomplete,
                },
            },
            summary: report.summary,
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
            unmatched: analysis::Sided {
                ingress: evidence_list(&report.unmatched.ingress)?,
                egress: evidence_list(&report.unmatched.egress)?,
            },
            unkeyed: analysis::Sided {
                ingress: report
                    .unkeyed
                    .ingress
                    .iter()
                    .map(Unkeyed::try_from)
                    .collect::<Result<_, _>>()?,
                egress: report
                    .unkeyed
                    .egress
                    .iter()
                    .map(Unkeyed::try_from)
                    .collect::<Result<_, _>>()?,
            },
            ambiguous: report
                .ambiguous
                .iter()
                .map(AmbiguousGroup::try_from)
                .collect::<Result<_, _>>()?,
            omitted: report.omitted,
        })
    }
}
