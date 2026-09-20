// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded comparison of two collected observation sets.
//!
//! [`verify`] indexes keyed observations by the exact encoded identity cells,
//! then resolves each key group once: 1:1 groups become matches with evaluated
//! checks, one-sided groups become unmatched observations, and many-to-many
//! groups stay ambiguous — members are listed, never greedily paired, and never
//! disambiguated by capture position or timestamp proximity.
//!
//! Everything reported derives from declared identity plus observation order:
//! reordering is flagged only when the egress order rank contradicts the
//! ingress order rank of uniquely matched pairs. Timestamps travel as
//! evidence only.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::limits::{DetailBudget, DetailCharge, ScratchBudget, json_bytes};
use super::{
    Error, ExpectationOutcome, Incomplete, Observation, Rules, Side, ValueState, VerifyLimits,
};
use crate::budget::{Cancellation, Deadline};
use crate::field::FieldValue;
use crate::frame::{GlobalInterfaceId, LinkType};

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
    fn from_rules(rules: &Rules) -> Self {
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

/// Compares the two collected observation sets under `rules`.
///
/// `max_details` bounds every report list; dropped entries are counted in
/// [`Report::omitted`] so a bounded document never looks complete. The
/// counters are always computed over the full evidence before any detail
/// bound applies.
pub fn verify(
    rules: &Rules,
    ingress: SideInput,
    egress: SideInput,
    max_details: usize,
    cancellation: Option<&Cancellation>,
) -> Result<Report, Error> {
    verify_with_limits(
        rules,
        ingress,
        egress,
        VerifyLimits {
            max_details,
            ..VerifyLimits::default()
        },
        cancellation,
        None,
    )
}

/// Comparison with independent scratch/detail budgets and an optional
/// invocation-wide deadline. A detail omission never changes the verdict.
/// Observations must originate from this exact compiled Rules instance.
pub fn verify_with_limits(
    rules: &Rules,
    ingress: SideInput,
    egress: SideInput,
    limits: VerifyLimits,
    cancellation: Option<&Cancellation>,
    deadline: Option<&Deadline>,
) -> Result<Report, Error> {
    let cancelled = |cancellation: Option<&Cancellation>| -> Result<(), Error> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        if let Some(deadline) = deadline {
            deadline.enforce()?;
        }
        Ok(())
    };
    cancelled(cancellation)?;
    rules.validate_observations(Side::Ingress, &ingress, || cancelled(cancellation))?;
    rules.validate_observations(Side::Egress, &egress, || cancelled(cancellation))?;
    let max_details = limits.max_details;
    let mut detail_budget = DetailBudget::new(limits.max_detail_bytes);
    let mut scratch_budget = ScratchBudget::new(limits.max_scratch_bytes);
    // Rank, order, permutation, and key-set bookkeeping. Charges are
    // independent of the observation collection budget, not an RSS cap.
    scratch_budget.reserve(
        ingress
            .observations
            .len()
            .saturating_add(egress.observations.len())
            .saturating_mul(192),
    )?;
    let sides = Sided {
        ingress: census(&ingress.observations, ingress.frames_read, || {
            cancelled(cancellation)
        })?,
        egress: census(&egress.observations, egress.frames_read, || {
            cancelled(cancellation)
        })?,
    };
    let ingress = ingress.observations;
    let egress = egress.observations;
    let ingress_index = index(&ingress, &mut scratch_budget, || cancelled(cancellation))?;
    let egress_index = index(&egress, &mut scratch_budget, || cancelled(cancellation))?;
    let ingress_rank = ranks(&ingress, || cancelled(cancellation))?;
    let egress_rank = ranks(&egress, || cancelled(cancellation))?;

    let mut summary = Summary::default();
    // Compute order over every unique pair, before retaining bounded details.
    let mut pair_orders = vec![None; ingress.len()];
    for (key, members) in &ingress_index {
        cancelled(cancellation)?;
        if let [member] = members.as_slice()
            && let Some(egress_members) = egress_index.get(key)
            && let [egress_member] = egress_members.as_slice()
        {
            pair_orders[*member] = Some(egress_rank[*egress_member]);
        }
    }
    let mut max_egress_order = 0;
    let reordered: Vec<bool> = pair_orders
        .into_iter()
        .map(|order| {
            let Some(order) = order else {
                return false;
            };
            let reordered = order < max_egress_order;
            max_egress_order = max_egress_order.max(order);
            summary.reordered_pairs += u64::from(reordered);
            reordered
        })
        .collect();

    let mut omitted = Omissions::default();
    let mut matches: Vec<Match> = Vec::new();
    let mut violations: Vec<Violation> = Vec::new();
    let mut unmatched: Sided<Vec<Evidence>> = Sided::default();
    let mut ambiguous: Vec<AmbiguousGroup> = Vec::new();

    let keys: BTreeSet<&Vec<u8>> = ingress_index.keys().chain(egress_index.keys()).collect();
    for key in keys {
        cancelled(cancellation)?;
        let ingress_members = ingress_index.get(key).map_or(&[][..], Vec::as_slice);
        let egress_members = egress_index.get(key).map_or(&[][..], Vec::as_slice);
        match (ingress_members.len(), egress_members.len()) {
            (0, 0) => unreachable!("identity keys always index at least one member"),
            (1, 1) => {
                summary.unique_matches += 1;
                let mut pair = evaluate_pair(
                    rules,
                    &ingress[ingress_members[0]],
                    &egress[egress_members[0]],
                    ingress_rank[ingress_members[0]],
                    egress_rank[egress_members[0]],
                    &mut summary,
                    &mut ViolationSink {
                        violations: &mut violations,
                        omitted: &mut omitted.violations,
                        max_details,
                        budget: &mut detail_budget,
                    },
                );
                pair.reordered = reordered[ingress_members[0]];
                push_bounded(
                    &mut matches,
                    &mut omitted.matches,
                    max_details,
                    &mut detail_budget,
                    pair,
                );
            }
            (ingress_count, 0) => {
                summary.ingress_only += ingress_count as u64;
                for member in ingress_members {
                    cancelled(cancellation)?;
                    push_bounded(
                        &mut unmatched.ingress,
                        &mut omitted.unmatched_ingress,
                        max_details,
                        &mut detail_budget,
                        Evidence::from(&ingress[*member]),
                    );
                }
            }
            (0, egress_count) => {
                summary.egress_only += egress_count as u64;
                for member in egress_members {
                    cancelled(cancellation)?;
                    let observation = &egress[*member];
                    record_egress_expectations(
                        rules,
                        observation,
                        &mut summary,
                        &mut ViolationSink {
                            violations: &mut violations,
                            omitted: &mut omitted.violations,
                            max_details,
                            budget: &mut detail_budget,
                        },
                    );
                    push_bounded(
                        &mut unmatched.egress,
                        &mut omitted.unmatched_egress,
                        max_details,
                        &mut detail_budget,
                        Evidence::from(observation),
                    );
                }
            }
            (ingress_count, egress_count) => {
                summary.ambiguous_groups += 1;
                summary.ambiguous_observations += (ingress_count + egress_count) as u64;
                for member in egress_members {
                    cancelled(cancellation)?;
                    record_egress_expectations(
                        rules,
                        &egress[*member],
                        &mut summary,
                        &mut ViolationSink {
                            violations: &mut violations,
                            omitted: &mut omitted.violations,
                            max_details,
                            budget: &mut detail_budget,
                        },
                    );
                }
                if ambiguous.len() < max_details
                    && detail_budget.reserve(1024usize.saturating_add(key.len()))
                {
                    let mut members =
                        |members: &[usize], pool: &[Observation]| -> Result<Vec<Evidence>, Error> {
                            let mut kept = Vec::new();
                            for member in members {
                                cancelled(cancellation)?;
                                push_bounded(
                                    &mut kept,
                                    &mut omitted.group_members,
                                    max_details,
                                    &mut detail_budget,
                                    Evidence::from(&pool[*member]),
                                );
                            }
                            Ok(kept)
                        };
                    ambiguous.push(AmbiguousGroup {
                        // Clone known cells rather than parsing serialized keys;
                        // decoder-defined nested values need no JSON depth round-trip.
                        key: ingress[ingress_members[0]].key().expect("indexed identity"),
                        ingress: members(ingress_members, &ingress)?,
                        egress: members(egress_members, &egress)?,
                        ingress_total: ingress_count as u64,
                        egress_total: egress_count as u64,
                        ingress_indistinguishable: indistinguishable(
                            ingress_members,
                            &ingress,
                            || cancelled(cancellation),
                        )?,
                        egress_indistinguishable: indistinguishable(
                            egress_members,
                            &egress,
                            || cancelled(cancellation),
                        )?,
                    });
                } else {
                    omitted.ambiguous_groups += 1;
                    omitted.group_members += (ingress_count + egress_count) as u64;
                }
            }
        }
    }

    // Expectation violations on unkeyed egress observations are still
    // attributable evidence: the observation itself failed the declared rule.
    for observation in &egress {
        cancelled(cancellation)?;
        if !observation.is_keyed() {
            record_egress_expectations(
                rules,
                observation,
                &mut summary,
                &mut ViolationSink {
                    violations: &mut violations,
                    omitted: &mut omitted.violations,
                    max_details,
                    budget: &mut detail_budget,
                },
            );
        }
    }

    // Matches publish in ingress order, independent of the detail ceiling.
    matches.sort_by_key(|pair| pair.ingress_order);

    let mut unkeyed = Sided::<Vec<UnkeyedObservation>>::default();
    for (observations, list, omitted_count) in [
        (&ingress, &mut unkeyed.ingress, &mut omitted.unkeyed_ingress),
        (&egress, &mut unkeyed.egress, &mut omitted.unkeyed_egress),
    ] {
        for observation in observations.iter().filter(|o| !o.is_keyed()) {
            cancelled(cancellation)?;
            push_bounded(
                list,
                omitted_count,
                max_details,
                &mut detail_budget,
                UnkeyedObservation {
                    evidence: Evidence::from(observation),
                    key: observation.key_cells.clone(),
                },
            );
        }
    }

    cancelled(cancellation)?;
    Ok(Report {
        verdict: verdict(&sides, &summary),
        rules: RequestedRules::from_rules(rules),
        assumptions: ASSUMPTIONS,
        sides,
        summary,
        matches,
        violations,
        unmatched,
        unkeyed,
        ambiguous,
        omitted,
    })
}

/// Counts one capture's observations into keyed/unkeyed/incomplete buckets.
fn census(
    observations: &[Observation],
    frames_read: u64,
    check: impl Fn() -> Result<(), Error>,
) -> Result<SideSummary, Error> {
    let mut summary = SideSummary {
        read: frames_read,
        ..SideSummary::default()
    };
    for observation in observations {
        check()?;
        summary.selected += 1;
        if observation.is_keyed() {
            summary.keyed += 1;
        } else {
            summary.unkeyed += 1;
        }
        summary.incomplete += u64::from(observation.incomplete.is_some());
    }
    Ok(summary)
}

/// Canonical identity bytes → observation indices, in capture order.
fn index(
    observations: &[Observation],
    budget: &mut ScratchBudget,
    check: impl Fn() -> Result<(), Error>,
) -> Result<BTreeMap<Vec<u8>, Vec<usize>>, Error> {
    let mut index: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    for (position, observation) in observations.iter().enumerate() {
        check()?;
        if observation.is_keyed() {
            let bytes = json_bytes(&observation.key_cells);
            budget.reserve(bytes.saturating_add(128))?;
            let key = serde_json::to_vec(&observation.key_cells)
                .expect("identity cells encode losslessly");
            index.entry(key).or_default().push(position);
        }
    }
    Ok(index)
}

/// Order ranks among keyed observations, aligned with `observations`.
fn ranks(
    observations: &[Observation],
    check: impl Fn() -> Result<(), Error>,
) -> Result<Vec<u64>, Error> {
    let mut rank = 0_u64;
    observations
        .iter()
        .map(|observation| {
            check()?;
            if observation.is_keyed() {
                let current = rank;
                rank += 1;
                Ok(current)
            } else {
                Ok(u64::MAX)
            }
        })
        .collect()
}

/// Whether every member carries identical projected non-identity evidence.
fn indistinguishable(
    members: &[usize],
    pool: &[Observation],
    check: impl Fn() -> Result<(), Error>,
) -> Result<bool, Error> {
    for pair in members.windows(2) {
        check()?;
        let (a, b) = (&pool[pair[0]], &pool[pair[1]]);
        if a.preserved != b.preserved
            || a.expectations != b.expectations
            || a.preserved_states != b.preserved_states
            || a.incomplete != b.incomplete
            || a.diagnostics != b.diagnostics
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The bounded violation list check outcomes record into.
struct ViolationSink<'a> {
    violations: &'a mut Vec<Violation>,
    omitted: &'a mut u64,
    max_details: usize,
    budget: &'a mut DetailBudget,
}

impl ViolationSink<'_> {
    /// Counts an outcome and, on violation, retains its evidence within the
    /// bound.
    fn record(
        &mut self,
        outcome: Outcome,
        summary: &mut Summary,
        violation: impl FnOnce() -> Violation,
    ) {
        match outcome {
            Outcome::Violated => {
                summary.checks_evaluated += 1;
                summary.checks_violated += 1;
                if self.violations.len() < self.max_details {
                    push_bounded(
                        self.violations,
                        self.omitted,
                        self.max_details,
                        self.budget,
                        violation(),
                    );
                } else {
                    *self.omitted += 1;
                }
            }
            Outcome::Satisfied => {
                summary.checks_evaluated += 1;
                summary.checks_satisfied += 1;
            }
            Outcome::Unevaluable => summary.checks_unevaluable += 1,
        }
    }
}

/// Evaluates one unique pairing and its declared checks.
fn evaluate_pair(
    rules: &Rules,
    ingress: &Observation,
    egress: &Observation,
    ingress_order: u64,
    egress_order: u64,
    summary: &mut Summary,
    sink: &mut ViolationSink<'_>,
) -> Match {
    let mut checks = Vec::with_capacity(rules.preserve.len() + rules.expectations.len());
    for (index, (kind, field)) in rules.preservation_specs().enumerate() {
        let expected = ingress.preserved[index].clone();
        let actual = egress.preserved[index].clone();
        let expected_state = ingress.preserved_states[index];
        let actual_state = egress.preserved_states[index];
        let outcome = preservation_outcome(kind, expected_state, actual_state, &expected, &actual);
        checks.push(CheckEvaluation {
            check: Check {
                kind,
                field: field.to_owned(),
                value: None,
            },
            outcome,
            expected_state: Some(expected_state),
            actual_state,
            expected: expected.clone(),
            actual: actual.clone(),
        });
        sink.record(outcome, summary, || Violation {
            check: Check {
                kind,
                field: field.to_owned(),
                value: None,
            },
            key: ingress.key(),
            ingress: Some(Evidence::from(ingress)),
            egress: Evidence::from(egress),
            expected,
            actual,
        });
    }
    for (expectation, stored) in rules.expectations.iter().zip(&egress.expectations) {
        let kind = expectation.kind();
        let field = &expectation.field;
        let declared = &expectation.declared;
        let (outcome, actual) = evaluate_expectation(kind, stored);
        checks.push(CheckEvaluation {
            check: Check {
                kind,
                field: field.to_owned(),
                value: (kind == CheckKind::Expect).then(|| declared.to_owned()),
            },
            outcome,
            expected_state: None,
            actual_state: stored.state,
            expected: None,
            actual: actual.clone(),
        });
        sink.record(outcome, summary, || Violation {
            check: Check {
                kind,
                field: field.to_owned(),
                value: (kind == CheckKind::Expect).then(|| declared.to_owned()),
            },
            key: egress.key(),
            ingress: Some(Evidence::from(ingress)),
            egress: Evidence::from(egress),
            expected: None,
            actual,
        });
    }
    Match {
        key: ingress.key().expect("a paired observation is keyed"),
        ingress: Evidence::from(ingress),
        egress: Evidence::from(egress),
        ingress_order,
        egress_order,
        reordered: false,
        checks,
    }
}

/// One egress observation's expectation outcomes, outside a unique pairing.
fn record_egress_expectations(
    rules: &Rules,
    egress: &Observation,
    summary: &mut Summary,
    sink: &mut ViolationSink<'_>,
) {
    for (expectation, stored) in rules.expectations.iter().zip(&egress.expectations) {
        let kind = expectation.kind();
        let (outcome, actual) = evaluate_expectation(kind, stored);
        sink.record(outcome, summary, || Violation {
            check: Check {
                kind,
                field: expectation.field.clone(),
                value: (kind == CheckKind::Expect).then(|| expectation.declared.clone()),
            },
            key: egress.key(),
            ingress: None,
            egress: Evidence::from(egress),
            expected: None,
            actual,
        });
    }
}

fn preservation_outcome(
    kind: CheckKind,
    expected_state: ValueState,
    actual_state: ValueState,
    expected: &Option<FieldValue>,
    actual: &Option<FieldValue>,
) -> Outcome {
    let equal = if kind == CheckKind::PreservePresence {
        expected_state
            .presence()
            .zip(actual_state.presence())
            .map(|(a, b)| a == b)
    } else if expected_state == ValueState::Observed && actual_state == ValueState::Observed {
        expected.as_ref().zip(actual.as_ref()).map(|(a, b)| a == b)
    } else {
        None
    };
    match equal {
        Some(true) => Outcome::Satisfied,
        Some(false) => Outcome::Violated,
        None => Outcome::Unevaluable,
    }
}

fn evaluate_expectation(
    kind: CheckKind,
    stored: &ExpectationOutcome,
) -> (Outcome, Option<FieldValue>) {
    let available = if kind == CheckKind::ExpectAbsent {
        stored.state.presence().is_some()
    } else {
        stored.state == ValueState::Observed && stored.actual.is_some()
    };
    let outcome = if !available {
        Outcome::Unevaluable
    } else if stored.satisfied {
        Outcome::Satisfied
    } else {
        Outcome::Violated
    };
    (outcome, stored.actual.clone())
}

/// Retains `item` while `list` is under `max`, counting the drop otherwise.
fn push_bounded<T: DetailCharge>(
    list: &mut Vec<T>,
    omitted: &mut u64,
    max: usize,
    budget: &mut DetailBudget,
    item: T,
) {
    if list.len() < max && budget.reserve(item.detail_charge()) {
        list.push(item);
    } else {
        *omitted += 1;
    }
}

/// The verdict from complete counters; detail omissions never change it.
fn verdict(sides: &Sided<SideSummary>, summary: &Summary) -> Verdict {
    if summary.checks_violated > 0 {
        return Verdict::Fail;
    }
    let incomplete = summary.ingress_only > 0
        || summary.egress_only > 0
        || summary.ambiguous_groups > 0
        || summary.checks_unevaluable > 0
        || sides.ingress.unkeyed > 0
        || sides.egress.unkeyed > 0
        || sides.ingress.incomplete > 0
        || sides.egress.incomplete > 0;
    // An empty selection can never pass: without keyed ingress observations
    // there is no correspondence evidence to evaluate at all.
    if incomplete || sides.ingress.keyed == 0 {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    }
}
