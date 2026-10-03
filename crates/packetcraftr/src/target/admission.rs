// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use super::ResolveTarget;
use super::selection::MAX_CANDIDATES;
use super::workflow::{SelectedTargets, approve_operation, resolve_selected};
use super::{Family, Selection, SelectionError, Specification, Target};
use crate::execution::Errors;
use crate::policy::{Authorizer, Operation};

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

pub(crate) struct DeclaredTargets<'a, E> {
    pub(crate) selection: &'a Selection,
    pub(crate) family: FamilyGate<E>,
    pub(crate) max_targets: usize,
}

/// Admits one declared target for a live operation: authorized resolution,
/// the empty/family gate, the workflow's budget plan over the admitted
/// addresses, then [`approve_operation`].
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
    A: Authorizer + ResolveTarget,
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
    A: Authorizer + ResolveTarget,
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
    A: Authorizer + ResolveTarget,
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

fn resolve_selection<A, G>(
    authorizer: &mut A,
    targets: DeclaredTargets<'_, G::Error>,
    deadline: &Deadline,
    gates: &G,
    invalid: impl Fn(SelectionError) -> G::Error,
) -> Result<SelectedTargets, G::Error>
where
    A: Authorizer + ResolveTarget,
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
    #![allow(dead_code)]

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::{Cancellation, Deadline, DeadlineExceeded, Interrupted};
    use packetcraftr_core::error::{Classification, Kind};

    use super::{DeclaredTargets, FamilyGate, admit_selection};
    use crate::StatsOverflow;
    use crate::execution::Errors;
    use crate::policy::{Authorizer, Operation};
    use crate::target::{Authorized, Family, Selection, SelectionError, Target, wire_limits};
    use packetcraftr_core::error::BoundaryError;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Resolve(Target),
        Approve(&'static str),
    }

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

    impl crate::target::ResolveTarget for RecordingAuthorizer {
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
    }

    impl Authorizer for RecordingAuthorizer {
        fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
            let shape = match operation {
                Operation::Socket(_) => "socket",
                Operation::Wire(_) => "wire",
                Operation::Dns(_) => "dns",
                Operation::Declared(_) => "declared-packet",
            };
            self.calls.push(Call::Approve(shape));
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
        Limit(&'static str),
        Step,
    }

    impl Errors for StubGates {
        type Error = StubError;
        type Step = ();

        fn invalid_limit(&self, field: &'static str, _: u64, _: String) -> StubError {
            StubError::Limit(field)
        }

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

        fn invalid_evidence(&self, (): (), _: crate::evidence::Error) -> StubError {
            StubError::Step
        }

        fn stats_overflow(&self, (): (), _: StatsOverflow) -> StubError {
            StubError::Step
        }
    }

    fn gate(family: Family) -> FamilyGate<StubError> {
        FamilyGate::new(family, |family| StubError::Family(family.label()))
    }

    fn selection_error(source: SelectionError) -> StubError {
        match source {
            SelectionError::Limit { field, .. } => StubError::Selection(field),
            _ => StubError::Selection("selection"),
        }
    }

    fn hostname() -> Target {
        Target::Hostname("documentation.invalid".parse().unwrap())
    }

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
}
