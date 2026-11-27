// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::limits::{DetailBudget, ScratchBudget, evidence_charge, json_bytes};
use super::report::{
    ASSUMPTIONS, AmbiguousGroup, Check, CheckEvaluation, CheckKind, Evidence, Match, Omissions,
    Outcome, Report, RequestedRules, SideSummary, Sided, Summary, UnkeyedObservation, Verdict,
    Violation,
};
use super::{Error, Expectation, ExpectationOutcome, Limits, Observation, Rules, Side, ValueState};
use crate::budget::{Cancellation, Deadline};
use crate::field;

#[derive(Clone, Debug, Default)]
pub struct SideInput {
    pub frames_read: u64,
    pub observations: Vec<Observation>,
}

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
        Limits {
            max_details,
            ..Limits::default()
        },
        cancellation,
        None,
    )
}

/// Observations must originate from this exact compiled Rules instance.
pub fn verify_with_limits(
    rules: &Rules,
    ingress: SideInput,
    egress: SideInput,
    limits: Limits,
    cancellation: Option<&Cancellation>,
    deadline: Option<&Deadline>,
) -> Result<Report, Error> {
    let check = || -> Result<(), Error> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        if let Some(deadline) = deadline {
            deadline.enforce()?;
        }
        Ok(())
    };
    check()?;
    rules.validate_observations(Side::Ingress, &ingress, check)?;
    rules.validate_observations(Side::Egress, &egress, check)?;
    let mut sink = ViolationSink {
        items: Vec::new(),
        omitted: 0,
        budget: DetailBudget::new(limits.max_details, limits.max_detail_bytes),
    };
    let mut scratch_budget = ScratchBudget::new(limits.max_scratch_bytes);
    scratch_budget.reserve(
        ingress
            .observations
            .len()
            .saturating_add(egress.observations.len())
            .saturating_mul(192),
    )?;
    let sides = Sided {
        ingress: census(&ingress.observations, ingress.frames_read, check)?,
        egress: census(&egress.observations, egress.frames_read, check)?,
    };
    let ingress = ingress.observations;
    let egress = egress.observations;
    let ingress_index = index(&ingress, &mut scratch_budget, check)?;
    let egress_index = index(&egress, &mut scratch_budget, check)?;
    let ingress_rank = ranks(&ingress, check)?;
    let egress_rank = ranks(&egress, check)?;

    let mut summary = Summary::default();
    // Compute order over every unique pair, before retaining bounded details.
    let mut pair_orders = vec![None; ingress.len()];
    for (key, members) in &ingress_index {
        check()?;
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
    let mut unmatched: Sided<Vec<Evidence>> = Sided::default();
    let mut ambiguous: Vec<AmbiguousGroup> = Vec::new();

    let keys: BTreeSet<&Vec<u8>> = ingress_index.keys().chain(egress_index.keys()).collect();
    for key in keys {
        check()?;
        let ingress_members = ingress_index.get(key).map_or(&[][..], Vec::as_slice);
        let egress_members = egress_index.get(key).map_or(&[][..], Vec::as_slice);
        match (ingress_members.len(), egress_members.len()) {
            (0, 0) => unreachable!("identity keys always index at least one member"),
            (1, 1) => {
                summary.unique_matches += 1;
                let pair = Pair {
                    ingress: &ingress[ingress_members[0]],
                    egress: &egress[egress_members[0]],
                    ingress_order: ingress_rank[ingress_members[0]],
                    egress_order: egress_rank[egress_members[0]],
                    reordered: reordered[ingress_members[0]],
                    key_bytes: key.len(),
                };
                if let Some(detail) =
                    evaluate_pair(rules, pair, &mut summary, &mut sink, matches.len())
                {
                    matches.push(detail);
                } else {
                    omitted.matches += 1;
                }
            }
            (ingress_count, 0) => {
                summary.ingress_only += ingress_count as u64;
                for member in ingress_members {
                    check()?;
                    push_evidence(
                        &mut unmatched.ingress,
                        &mut omitted.unmatched_ingress,
                        &mut sink.budget,
                        &ingress[*member],
                    );
                }
            }
            (0, egress_count) => {
                summary.egress_only += egress_count as u64;
                for member in egress_members {
                    check()?;
                    let observation = &egress[*member];
                    record_egress_expectations(rules, observation, &mut summary, &mut sink);
                    push_evidence(
                        &mut unmatched.egress,
                        &mut omitted.unmatched_egress,
                        &mut sink.budget,
                        observation,
                    );
                }
            }
            (ingress_count, egress_count) => {
                summary.ambiguous_groups += 1;
                summary.ambiguous_observations += (ingress_count + egress_count) as u64;
                for member in egress_members {
                    check()?;
                    record_egress_expectations(rules, &egress[*member], &mut summary, &mut sink);
                }
                if sink.budget.has_slot(ambiguous.len())
                    && sink.budget.reserve(1024usize.saturating_add(key.len()))
                {
                    let mut members =
                        |members: &[usize], pool: &[Observation]| -> Result<Vec<Evidence>, Error> {
                            let mut kept = Vec::new();
                            for member in members {
                                check()?;
                                push_evidence(
                                    &mut kept,
                                    &mut omitted.group_members,
                                    &mut sink.budget,
                                    &pool[*member],
                                );
                            }
                            Ok(kept)
                        };
                    ambiguous.push(AmbiguousGroup {
                        key: ingress[ingress_members[0]].key().expect("indexed identity"),
                        ingress: members(ingress_members, &ingress)?,
                        egress: members(egress_members, &egress)?,
                        ingress_total: ingress_count as u64,
                        egress_total: egress_count as u64,
                        ingress_indistinguishable: indistinguishable(
                            ingress_members,
                            &ingress,
                            check,
                        )?,
                        egress_indistinguishable: indistinguishable(
                            egress_members,
                            &egress,
                            check,
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
        check()?;
        if !observation.is_keyed() {
            record_egress_expectations(rules, observation, &mut summary, &mut sink);
        }
    }

    matches.sort_by_key(|pair| pair.ingress_order);

    let mut unkeyed = Sided::<Vec<UnkeyedObservation>>::default();
    for (observations, list, omitted_count) in [
        (&ingress, &mut unkeyed.ingress, &mut omitted.unkeyed_ingress),
        (&egress, &mut unkeyed.egress, &mut omitted.unkeyed_egress),
    ] {
        for observation in observations.iter().filter(|o| !o.is_keyed()) {
            check()?;
            push_bounded(
                list,
                omitted_count,
                &mut sink.budget,
                || {
                    128usize
                        .saturating_add(evidence_charge(observation))
                        .saturating_add(json_bytes(&observation.key_cells))
                },
                || UnkeyedObservation {
                    evidence: Evidence::from(observation),
                    key: observation.key_cells.clone(),
                },
            );
        }
    }

    check()?;
    omitted.violations = sink.omitted;
    Ok(Report {
        verdict: verdict(&sides, &summary),
        rules: RequestedRules::from_rules(rules),
        assumptions: ASSUMPTIONS,
        sides,
        summary,
        matches,
        violations: sink.items,
        unmatched,
        unkeyed,
        ambiguous,
        omitted,
    })
}

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

fn index(
    observations: &[Observation],
    budget: &mut ScratchBudget,
    check: impl Fn() -> Result<(), Error>,
) -> Result<BTreeMap<Vec<u8>, Vec<usize>>, Error> {
    let mut index: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    for (position, observation) in observations.iter().enumerate() {
        check()?;
        if observation.is_keyed() {
            budget.reserve(128)?;
            let key = budget.json(&observation.key_cells)?;
            index.entry(key).or_default().push(position);
        }
    }
    Ok(index)
}

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

#[derive(Clone, Copy, Serialize)]
struct CheckRef<'a> {
    kind: CheckKind,
    field: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
}

impl From<CheckRef<'_>> for Check {
    fn from(check: CheckRef<'_>) -> Self {
        Self {
            kind: check.kind,
            field: check.field.to_owned(),
            value: check.value.map(str::to_owned),
        }
    }
}

#[derive(Clone, Copy, Serialize)]
struct Evaluation<'a> {
    check: CheckRef<'a>,
    outcome: Outcome,
    expected_state: Option<ValueState>,
    actual_state: ValueState,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<&'a field::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual: Option<&'a field::Value>,
}

impl From<Evaluation<'_>> for CheckEvaluation {
    fn from(evaluation: Evaluation<'_>) -> Self {
        Self {
            check: evaluation.check.into(),
            outcome: evaluation.outcome,
            expected_state: evaluation.expected_state,
            actual_state: evaluation.actual_state,
            expected: evaluation.expected.cloned(),
            actual: evaluation.actual.cloned(),
        }
    }
}

struct ViolationSink {
    items: Vec<Violation>,
    omitted: u64,
    budget: DetailBudget,
}

impl ViolationSink {
    fn record(
        &mut self,
        evaluation: Evaluation<'_>,
        summary: &mut Summary,
        key: &Observation,
        ingress: Option<&Observation>,
        egress: &Observation,
    ) {
        match evaluation.outcome {
            Outcome::Violated => {
                summary.checks_evaluated += 1;
                summary.checks_violated += 1;
                push_bounded(
                    &mut self.items,
                    &mut self.omitted,
                    &mut self.budget,
                    || {
                        let key = key.is_keyed().then_some(key.key_cells.as_slice());
                        512usize
                            .saturating_add(json_bytes(&evaluation.check))
                            .saturating_add(json_bytes(&key))
                            .saturating_add(ingress.map_or(0, evidence_charge))
                            .saturating_add(evidence_charge(egress))
                            .saturating_add(json_bytes(&evaluation.expected))
                            .saturating_add(json_bytes(&evaluation.actual))
                    },
                    || Violation {
                        check: evaluation.check.into(),
                        key: key.key(),
                        ingress: ingress.map(Evidence::from),
                        egress: Evidence::from(egress),
                        expected: evaluation.expected.cloned(),
                        actual: evaluation.actual.cloned(),
                    },
                );
            }
            Outcome::Satisfied => {
                summary.checks_evaluated += 1;
                summary.checks_satisfied += 1;
            }
            Outcome::Unevaluable => summary.checks_unevaluable += 1,
        }
    }
}

struct Pair<'a> {
    ingress: &'a Observation,
    egress: &'a Observation,
    ingress_order: u64,
    egress_order: u64,
    reordered: bool,
    key_bytes: usize,
}

fn evaluate_pair(
    rules: &Rules,
    pair: Pair<'_>,
    summary: &mut Summary,
    sink: &mut ViolationSink,
    retained_matches: usize,
) -> Option<Match> {
    let Pair {
        ingress,
        egress,
        ingress_order,
        egress_order,
        reordered,
        key_bytes,
    } = pair;
    let minimum_charge = 1536usize.saturating_add(key_bytes);
    let mut checks = sink
        .budget
        .can_fit(retained_matches, minimum_charge)
        .then(Vec::new);
    for (index, (kind, field)) in rules.preservation_specs().enumerate() {
        let expected = ingress.preserved[index].as_ref();
        let actual = egress.preserved[index].as_ref();
        let expected_state = ingress.preserved_states[index];
        let actual_state = egress.preserved_states[index];
        let evaluation = Evaluation {
            check: CheckRef {
                kind,
                field,
                value: None,
            },
            outcome: preservation_outcome(kind, expected_state, actual_state, expected, actual),
            expected_state: Some(expected_state),
            actual_state,
            expected,
            actual,
        };
        if let Some(checks) = &mut checks {
            checks.push(evaluation);
        }
        sink.record(evaluation, summary, ingress, Some(ingress), egress);
    }
    for (expectation, stored) in rules.expectations.iter().zip(&egress.expectations) {
        let evaluation = evaluate_expectation(expectation, stored);
        if let Some(checks) = &mut checks {
            checks.push(evaluation);
        }
        sink.record(evaluation, summary, egress, Some(ingress), egress);
    }
    let checks = checks?;
    if !sink.budget.can_fit(retained_matches, minimum_charge) {
        return None;
    }
    let charge = 512usize
        .saturating_add(key_bytes)
        .saturating_add(evidence_charge(ingress))
        .saturating_add(evidence_charge(egress))
        .saturating_add(json_bytes(&checks));
    sink.budget.reserve(charge).then(|| Match {
        key: ingress.key().expect("a paired observation is keyed"),
        ingress: Evidence::from(ingress),
        egress: Evidence::from(egress),
        ingress_order,
        egress_order,
        reordered,
        checks: checks.into_iter().map(CheckEvaluation::from).collect(),
    })
}

fn record_egress_expectations(
    rules: &Rules,
    egress: &Observation,
    summary: &mut Summary,
    sink: &mut ViolationSink,
) {
    for (expectation, stored) in rules.expectations.iter().zip(&egress.expectations) {
        sink.record(
            evaluate_expectation(expectation, stored),
            summary,
            egress,
            None,
            egress,
        );
    }
}

fn preservation_outcome(
    kind: CheckKind,
    expected_state: ValueState,
    actual_state: ValueState,
    expected: Option<&field::Value>,
    actual: Option<&field::Value>,
) -> Outcome {
    let equal = if kind == CheckKind::PreservePresence {
        expected_state
            .presence()
            .zip(actual_state.presence())
            .map(|(a, b)| a == b)
    } else if expected_state == ValueState::Observed && actual_state == ValueState::Observed {
        expected.zip(actual).map(|(a, b)| a == b)
    } else {
        None
    };
    match equal {
        Some(true) => Outcome::Satisfied,
        Some(false) => Outcome::Violated,
        None => Outcome::Unevaluable,
    }
}

fn evaluate_expectation<'a>(
    expectation: &'a Expectation,
    stored: &'a ExpectationOutcome,
) -> Evaluation<'a> {
    let kind = expectation.kind();
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
    Evaluation {
        check: CheckRef {
            kind,
            field: &expectation.field,
            value: (kind == CheckKind::Expect).then_some(expectation.declared.as_str()),
        },
        outcome,
        expected_state: None,
        actual_state: stored.state,
        expected: None,
        actual: stored.actual.as_ref(),
    }
}

fn push_evidence(
    list: &mut Vec<Evidence>,
    omitted: &mut u64,
    budget: &mut DetailBudget,
    observation: &Observation,
) {
    push_bounded(
        list,
        omitted,
        budget,
        || evidence_charge(observation),
        || Evidence::from(observation),
    );
}

fn push_bounded<T>(
    list: &mut Vec<T>,
    omitted: &mut u64,
    budget: &mut DetailBudget,
    charge: impl FnOnce() -> usize,
    item: impl FnOnce() -> T,
) {
    if budget.can_fit(list.len(), 1) && budget.reserve(charge()) {
        list.push(item());
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
