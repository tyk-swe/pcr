// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded comparison by declared identity. [`verify`] pairs only 1:1 groups;
//! one-sided groups are unmatched and non-1:1 groups remain ambiguous. Neither
//! position nor timestamps disambiguate members. Reordering compares uniquely
//! matched pairs' ingress/egress ranks; timestamps are evidence only.

use std::collections::{BTreeMap, BTreeSet};

use super::limits::{DetailBudget, DetailCharge, ScratchBudget, json_bytes};
use super::{Error, ExpectationOutcome, Observation, Rules, Side, ValueState, VerifyLimits};
use crate::budget::{Cancellation, Deadline};
use crate::field::FieldValue;

use super::report::{
    ASSUMPTIONS, AmbiguousGroup, Check, CheckEvaluation, CheckKind, Evidence, Match, Omissions,
    Outcome, Report, RequestedRules, SideInput, SideSummary, Sided, Summary, UnkeyedObservation,
    Verdict, Violation,
};

/// Compares observations under `rules`. Counters cover all evidence;
/// `max_details` bounds each report list, with exclusions counted in
/// [`Report::omitted`].
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
