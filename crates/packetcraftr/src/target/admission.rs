// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation admission for live workflows.
//!
//! Admission owns the ordering between a declared target set and the first
//! live side effect: authorized resolution, the empty/family gate, the
//! workflow's worst-case budget arithmetic, then [`approve_operation`]. Two
//! workflows deliberately compose the lower-level gates instead: DNS approves
//! [`Operation::Dns`] before any server resolution (destination authorization
//! follows budget approval for that shape), and fuzz admits declared packets
//! with no declared target to resolve.

use std::collections::HashSet;
use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use super::selection::MAX_CANDIDATES;
use super::workflow::{SelectedTargets, approve_operation, resolve_selected};
use super::{Family, Selection, SelectionError, Specification, Target};
use crate::execution::Errors;
use crate::policy::{Authorizer, Operation};

/// The address family every admitted address must belong to, and how the
/// workflow names an authorized resolution that holds none.
pub(crate) struct FamilyGate<E> {
    family: Family,
    unavailable: fn(Family) -> E,
}

impl<E> FamilyGate<E> {
    pub(crate) const fn new(family: Family, unavailable: fn(Family) -> E) -> Self {
        Self {
            family,
            unavailable,
        }
    }

    pub(crate) const fn family(&self) -> Family {
        self.family
    }

    /// The empty/family gate every admitted resolution passes before budget
    /// planning: an authorized set holding no address of the family fails
    /// the operation.
    pub(crate) fn require(&self, addresses: &[IpAddr]) -> Result<(), E> {
        if addresses.is_empty() {
            return Err((self.unavailable)(self.family));
        }
        Ok(())
    }
}

impl<E> Clone for FamilyGate<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for FamilyGate<E> {}

/// The declared set [`admit_selection`] resolves and admits: the selection to
/// expand, the family every admitted address must match, and the bound on
/// admitted addresses.
pub(crate) struct DeclaredTargets<'a, E> {
    pub(crate) selection: &'a Selection,
    pub(crate) family: FamilyGate<E>,
    pub(crate) max_targets: usize,
}

/// Admits one declared target for a live operation: authorized resolution,
/// the empty/family gate, the workflow's budget plan over the admitted
/// addresses, then [`approve_operation`].
///
/// Request validation stays with the caller before this call. `plan` runs the
/// workflow's budget arithmetic — unit count, worst-case wire bytes and
/// duration — and `operation` builds the approved shape from it, so an
/// [`Operation`] may borrow the plan for the duration of the approval call.
/// The returned selection is the family-filtered, deduplicated address set
/// the operation may address.
pub(crate) fn admit_operation<A, G, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: &G,
    target: &Target,
    family: FamilyGate<G::Error>,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), G::Error>
where
    A: Authorizer,
    G: Errors,
    Plan: FnOnce(&SelectedTargets) -> Result<P, G::Error>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, G::Error>,
{
    let selected = resolve_selected(authorizer, target, family.family(), deadline, gates)?;
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

/// [`admit_operation`] over a declared [`Selection`].
///
/// Each distinct specification is expanded and authorized once, in declared
/// order; an oversized network fails through `invalid` before any of its own
/// addresses reach the authorizer, though earlier specifications may already
/// have been authorized; numeric addresses already excluded, seen, or
/// family-mismatched are skipped without spending an authorization call; and
/// admitted addresses are deduplicated and capped at `targets.max_targets` in
/// declared order.
pub(crate) fn admit_selection<A, G, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: &G,
    targets: DeclaredTargets<'_, G::Error>,
    invalid: impl Fn(SelectionError) -> G::Error,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), G::Error>
where
    A: Authorizer,
    G: Errors,
    Plan: FnOnce(&SelectedTargets) -> Result<P, G::Error>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, G::Error>,
{
    let family = targets.family;
    let selected = resolve_selection(authorizer, targets, deadline, gates, invalid)?;
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

/// Gate → plan → approve over an already-authorized selection.
fn admit_selected<A, G, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: &G,
    family: FamilyGate<G::Error>,
    selected: SelectedTargets,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), G::Error>
where
    A: Authorizer,
    G: Errors,
    Plan: FnOnce(&SelectedTargets) -> Result<P, G::Error>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, G::Error>,
{
    family.require(&selected.addresses)?;
    let plan = plan(&selected)?;
    let operation = operation(&plan)?;
    approve_operation(authorizer, operation, deadline, gates)?;
    Ok((selected, plan))
}

/// Expands a declared selection into authorized addresses, checking the
/// deadline's cooperative `enforce` gate inside both loops.
fn resolve_selection<A, G>(
    authorizer: &mut A,
    targets: DeclaredTargets<'_, G::Error>,
    deadline: &Deadline,
    gates: &G,
    invalid: impl Fn(SelectionError) -> G::Error,
) -> Result<SelectedTargets, G::Error>
where
    A: Authorizer,
    G: Errors,
{
    let DeclaredTargets {
        selection,
        family,
        max_targets,
    } = targets;
    let family = family.family();
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    let mut specifications = HashSet::new();
    let mut candidates = 0usize;
    for specification in &selection.include {
        if !specifications.insert(specification) {
            continue;
        }
        let expanded: Box<dyn Iterator<Item = Target> + '_> = match specification {
            Specification::Target(target) => Box::new(std::iter::once(target.clone())),
            Specification::Network(network) => Box::new(
                network
                    .addresses(MAX_CANDIDATES)
                    .map_err(&invalid)?
                    .map(Target::Address),
            ),
        };
        for target in expanded {
            deadline
                .enforce()
                .map_err(|source| gates.interrupted(G::Step::default(), source))?;
            candidates = candidates
                .checked_add(1)
                .filter(|count| *count <= MAX_CANDIDATES)
                .ok_or_else(|| {
                    invalid(SelectionError::Limit {
                        field: "target_candidates",
                        limit: MAX_CANDIDATES,
                    })
                })?;
            if let Target::Address(address) = target
                && (selection.excludes(address)
                    || seen.contains(&address)
                    || !family.accepts(address))
            {
                continue;
            }
            let resolved = resolve_selected(authorizer, &target, family, deadline, gates)?;
            for address in resolved.addresses {
                deadline
                    .enforce()
                    .map_err(|source| gates.interrupted(G::Step::default(), source))?;
                if selection.excludes(address) || !seen.insert(address) {
                    continue;
                }
                if selected.len() >= max_targets {
                    return Err(invalid(SelectionError::Limit {
                        field: "max_targets",
                        limit: max_targets,
                    }));
                }
                selected.push(address);
            }
        }
    }
    Ok(SelectedTargets {
        declared: selection.to_string(),
        addresses: selected,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::{Cancellation, Deadline, DeadlineExceeded, Interrupted};
    use packetcraftr_core::error::{Classification, Kind};

    use super::{DeclaredTargets, FamilyGate, admit_operation, admit_selection};
    use crate::execution::{Errors, ExchangeEvidenceError};
    use crate::policy::{Authorizer, Operation, SocketLimits, SocketOperation};
    use crate::target::{Authorized, Family, Selection, SelectionError, Target, wire_limits};
    use crate::{BoundaryError, StatsOverflow};

    /// One authorizer boundary call, in order.
    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Resolve(Target),
        Approve(&'static str),
    }

    /// Records the call sequence and scripts refusals, cancellation, and a
    /// clock jump so the admission ordering is asserted without sockets, real
    /// resolution, or execution.
    #[derive(Default)]
    struct RecordingAuthorizer {
        calls: Vec<Call>,
        answers: Vec<IpAddr>,
        deny_target: bool,
        deny_operation: bool,
        cancel: Option<Cancellation>,
        clock: Option<Arc<Mutex<Instant>>>,
        expired_at: Option<Instant>,
    }

    impl Authorizer for RecordingAuthorizer {
        fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
            self.calls.push(Call::Resolve(target.clone()));
            if let Some(cancellation) = &self.cancel {
                cancellation.cancel();
            }
            if self.deny_target {
                return Err(boundary("the fixture denied the declared target"));
            }
            let addresses = match target {
                Target::Address(address) => vec![*address],
                Target::Hostname(_) => self.answers.clone(),
            };
            Ok(Authorized {
                declared: target.clone(),
                addresses,
            })
        }

        fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
            self.calls.push(Call::Approve(operation.shape()));
            if let Some(cancellation) = &self.cancel {
                cancellation.cancel();
            }
            if let (Some(clock), Some(expired_at)) = (&self.clock, self.expired_at) {
                *clock.lock().unwrap() = expired_at;
            }
            if self.deny_operation {
                return Err(boundary("the fixture denied the operation budget"));
            }
            Ok(())
        }
    }

    fn boundary(message: &'static str) -> BoundaryError {
        BoundaryError::new(
            message,
            Classification::new("policy.fixture", Kind::Policy, None),
            Vec::new(),
        )
    }

    /// A gate adapter whose marker errors identify which method produced them.
    struct StubGates;

    #[derive(Debug, PartialEq, Eq)]
    enum StubError {
        DurationLimit,
        Authorization,
        Interrupted,
        Family(&'static str),
        Selection(&'static str),
        Plan,
        Operation,
        /// A step failure, which admission never raises.
        Step,
    }

    impl Errors for StubGates {
        type Error = StubError;
        type Step = ();

        fn authorization(&self, _: BoundaryError) -> StubError {
            StubError::Authorization
        }

        fn duration_limit(&self, (): (), _: DeadlineExceeded) -> StubError {
            StubError::DurationLimit
        }

        fn interrupted(&self, (): (), _: Interrupted) -> StubError {
            StubError::Interrupted
        }

        fn clock(&self, (): (), _: Box<dyn std::error::Error + Send + Sync>) -> StubError {
            StubError::Step
        }

        fn execution(&self, (): (), _: BoundaryError) -> StubError {
            StubError::Step
        }

        fn invalid_evidence(&self, (): (), _: ExchangeEvidenceError) -> StubError {
            StubError::Step
        }

        fn stats_overflow(&self, (): (), _: StatsOverflow) -> StubError {
            StubError::Step
        }
    }

    /// The family gate naming a miss as the stub's marker error.
    fn gate(family: Family) -> FamilyGate<StubError> {
        FamilyGate::new(family, |family| StubError::Family(family.label()))
    }

    /// Selection-expansion failures surface as their bounded `field` name.
    fn selection_error(source: SelectionError) -> StubError {
        match source {
            SelectionError::Limit { field, .. } => StubError::Selection(field),
            _ => StubError::Selection("selection"),
        }
    }

    fn target() -> Target {
        Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    }

    fn hostname() -> Target {
        Target::Hostname("documentation.invalid".parse().unwrap())
    }

    /// Target authorization precedes the operation approval: the call order
    /// is resolve, then approve — never approve first.
    #[test]
    fn target_authorization_precedes_budget_approval() {
        let mut authorizer = RecordingAuthorizer::default();
        let (selected, probes) = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &target(),
            gate(Family::Any),
            |selected| Ok(u64::try_from(selected.addresses.len()).unwrap_or(u64::MAX)),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect("admission succeeds");
        assert_eq!(selected.declared, "192.0.2.1");
        assert_eq!(
            selected.addresses,
            [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
        assert_eq!(probes, 1);
        assert_eq!(
            authorizer.calls,
            [Call::Resolve(target()), Call::Approve("wire")]
        );
    }

    /// A denied declared target stops admission before `authorize_operation`.
    #[test]
    fn declared_target_denial_short_circuits_approval() {
        let mut authorizer = RecordingAuthorizer {
            deny_target: true,
            ..Default::default()
        };
        let error = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("target denial must stop admission");
        assert_eq!(error, StubError::Authorization);
        assert_eq!(authorizer.calls, [Call::Resolve(target())]);
    }

    /// The empty/family gate runs after resolution and before budget planning
    /// and approval.
    #[test]
    fn a_family_mismatched_resolution_gates_before_approval() {
        let mut authorizer = RecordingAuthorizer {
            answers: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            ..Default::default()
        };
        let planned = std::cell::Cell::new(false);
        let error = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &hostname(),
            gate(Family::Ipv4),
            |_| {
                planned.set(true);
                Ok(1_u64)
            },
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("an answer set with no IPv4 address must be gated");
        assert_eq!(error, StubError::Family("IPv4"));
        assert!(!planned.get(), "the plan closure must not run");
        assert_eq!(authorizer.calls, [Call::Resolve(hostname())]);
    }

    /// A budget-arithmetic failure stops admission before approval.
    #[test]
    fn a_failed_budget_plan_skips_approval() {
        let mut authorizer = RecordingAuthorizer::default();
        let error = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Err(StubError::Plan),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("a failed plan must stop admission");
        assert_eq!(error, StubError::Plan);
        assert_eq!(authorizer.calls, [Call::Resolve(target())]);
    }

    /// A failure building the operation — an over-budget socket set, for
    /// example — stops admission before approval.
    #[test]
    fn a_failed_operation_build_skips_approval() {
        let mut authorizer = RecordingAuthorizer::default();
        let error = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Ok(1_u64),
            |_| Err(StubError::Operation),
        )
        .expect_err("a failed operation build must stop admission");
        assert_eq!(error, StubError::Operation);
        assert_eq!(authorizer.calls, [Call::Resolve(target())]);
    }

    /// Borrowed operation shapes stay alive through approval: the plan owns
    /// the endpoints `Operation::Socket` borrows.
    #[test]
    fn borrowed_operations_survive_the_approval_call() {
        let mut authorizer = RecordingAuthorizer::default();
        let (_, endpoints) = admit_operation(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| {
                Ok(vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    80,
                )])
            },
            |endpoints| {
                SocketOperation::new(endpoints, SocketLimits::new(1, 0, 0))
                    .map(Operation::Socket)
                    .map_err(|_| StubError::Operation)
            },
        )
        .expect("admission succeeds");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            authorizer.calls,
            [Call::Resolve(target()), Call::Approve("socket")]
        );
    }

    /// The same gate failure surfaces in each workflow's own vocabulary.
    #[test]
    fn gate_errors_surface_the_workflow_vocabulary() {
        for workflow in [
            crate::probe::Workflow::Scan,
            crate::probe::Workflow::Traceroute,
        ] {
            let mut authorizer = RecordingAuthorizer {
                answers: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                ..Default::default()
            };
            let unavailable: fn(Family) -> crate::probe::Error = match workflow {
                crate::probe::Workflow::Scan => {
                    |family| crate::probe::Workflow::Scan.family(family)
                }
                crate::probe::Workflow::Traceroute => {
                    |family| crate::probe::Workflow::Traceroute.family(family)
                }
            };
            let error = admit_operation(
                &mut authorizer,
                &Deadline::new(Duration::from_secs(60)),
                &workflow,
                &hostname(),
                FamilyGate::new(Family::Ipv4, unavailable),
                |_| Ok(1_u64),
                |probes| Ok(wire_limits(*probes, 0)),
            )
            .expect_err("the family gate must fail");
            assert_eq!(error.workflow, workflow);
            assert!(matches!(
                error.kind,
                crate::probe::ErrorKind::Family { family: "IPv4" }
            ));
            assert_eq!(authorizer.calls, [Call::Resolve(hostname())]);
        }
    }

    /// An already-spent deadline fails before the authorizer is called at all.
    #[test]
    fn a_spent_deadline_precedes_target_authorization() {
        let mut deadline = Deadline::new(Duration::from_secs(1));
        let _ = deadline.account(Duration::from_secs(2));
        let mut authorizer = RecordingAuthorizer::default();
        let error = admit_operation(
            &mut authorizer,
            &deadline,
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("a spent deadline must stop admission");
        assert_eq!(error, StubError::DurationLimit);
        assert!(authorizer.calls.is_empty());
    }

    /// A deadline spent inside `authorize_operation` reports the duration
    /// error even when the authorizer also refused.
    #[test]
    fn a_deadline_spent_in_authorization_outranks_denial() {
        let now = Arc::new(Mutex::new(Instant::now()));
        let baseline = *now.lock().unwrap();
        let clock = Arc::clone(&now);
        let deadline =
            Deadline::with_time_source(Duration::from_secs(1), move || *clock.lock().unwrap());
        let mut authorizer = RecordingAuthorizer {
            deny_operation: true,
            clock: Some(now),
            expired_at: Some(baseline + Duration::from_secs(2)),
            ..Default::default()
        };
        let error = admit_operation(
            &mut authorizer,
            &deadline,
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("the spent deadline must be reported");
        assert_eq!(error, StubError::DurationLimit);
        assert_eq!(
            authorizer.calls,
            [Call::Resolve(target()), Call::Approve("wire")]
        );
    }

    /// `admit_operation`'s gates check elapsed time only: cancellation raised
    /// inside the authorizer completes the call and surfaces at the caller's
    /// next cooperative `enforce` boundary, matching the engines' existing
    /// placement.
    #[test]
    fn cancellation_deferred_to_the_next_cooperative_boundary() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let mut authorizer = RecordingAuthorizer {
            cancel: Some(signal),
            ..Default::default()
        };
        let (selected, _) = admit_operation(
            &mut authorizer,
            &deadline,
            &StubGates,
            &target(),
            gate(Family::Any),
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect("elapsed-time gates do not observe cancellation");
        assert_eq!(selected.addresses.len(), 1);
        assert_eq!(
            authorizer.calls,
            [Call::Resolve(target()), Call::Approve("wire")]
        );
        assert!(matches!(deadline.enforce(), Err(Interrupted::Cancelled(_))));
    }

    /// Numeric candidates the selection already excluded, already expanded,
    /// or the family cannot use never reach the authorizer.
    #[test]
    fn selection_skips_filtered_numeric_candidates_before_authorization() {
        let selection = Selection {
            include: vec![
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "::1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "documentation.invalid".parse().unwrap(),
            ],
            exclude: vec!["192.0.2.1".parse().unwrap()],
        };
        let mut authorizer = RecordingAuthorizer {
            answers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))],
            ..Default::default()
        };
        let (selected, probes) = admit_selection(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            DeclaredTargets {
                selection: &selection,
                family: gate(Family::Ipv4),
                max_targets: 16,
            },
            selection_error,
            |selected| Ok(u64::try_from(selected.addresses.len()).unwrap_or(u64::MAX)),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect("admission succeeds");
        assert_eq!(probes, 2);
        assert_eq!(
            selected.addresses,
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            ]
        );
        assert_eq!(
            selected.declared,
            "192.0.2.1,192.0.2.2,::1,192.0.2.2,documentation.invalid,!192.0.2.1/32"
        );
        assert_eq!(
            authorizer.calls,
            [
                Call::Resolve(Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))),
                Call::Resolve(hostname()),
                Call::Approve("wire"),
            ]
        );
    }

    /// The `max_targets` bound fails through the caller's selection adapter
    /// without an approval call.
    #[test]
    fn selection_caps_admitted_addresses_through_the_adapter() {
        let selection = Selection {
            include: vec!["documentation.invalid".parse().unwrap()],
            exclude: Vec::new(),
        };
        let mut authorizer = RecordingAuthorizer {
            answers: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            ],
            ..Default::default()
        };
        let error = admit_selection(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            DeclaredTargets {
                selection: &selection,
                family: gate(Family::Any),
                max_targets: 1,
            },
            selection_error,
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("the address cap must stop admission");
        assert_eq!(error, StubError::Selection("max_targets"));
        assert_eq!(authorizer.calls, [Call::Resolve(hostname())]);
    }

    /// An oversized network fails before any authorizer call.
    #[test]
    fn oversized_networks_fail_before_authorization() {
        let selection = Selection {
            include: vec!["::/0".parse().unwrap()],
            exclude: Vec::new(),
        };
        let mut authorizer = RecordingAuthorizer::default();
        let error = admit_selection(
            &mut authorizer,
            &Deadline::new(Duration::from_secs(60)),
            &StubGates,
            DeclaredTargets {
                selection: &selection,
                family: gate(Family::Any),
                max_targets: 16,
            },
            selection_error,
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("an oversized network must fail before authorization");
        assert_eq!(error, StubError::Selection("target_candidates"));
        assert!(authorizer.calls.is_empty());
    }

    /// The expansion loop keeps its cooperative gate: cancellation raised
    /// inside `resolve_and_authorize` stops admission before approval.
    #[test]
    fn selection_expansion_stops_at_cancellation() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let selection = Selection {
            include: vec!["documentation.invalid".parse().unwrap()],
            exclude: Vec::new(),
        };
        let mut authorizer = RecordingAuthorizer {
            answers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))],
            cancel: Some(signal),
            ..Default::default()
        };
        let error = admit_selection(
            &mut authorizer,
            &deadline,
            &StubGates,
            DeclaredTargets {
                selection: &selection,
                family: gate(Family::Any),
                max_targets: 16,
            },
            selection_error,
            |_| Ok(1_u64),
            |probes| Ok(wire_limits(*probes, 0)),
        )
        .expect_err("cancellation inside resolution must stop admission");
        assert_eq!(error, StubError::Interrupted);
        assert_eq!(authorizer.calls, [Call::Resolve(hostname())]);
    }

    /// The family gate is the shared empty-selection gate for workflows that
    /// compose the lower-level pieces directly.
    #[test]
    fn the_family_gate_rejects_an_empty_address_set() {
        assert_eq!(
            gate(Family::Ipv6).require(&[]),
            Err(StubError::Family("IPv6"))
        );
        assert_eq!(
            gate(Family::Ipv4).require(&[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]),
            Ok(())
        );
    }
}
