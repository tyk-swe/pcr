// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface::Id as InterfaceId;

use super::ResolveTarget;
use super::selection::MAX_CANDIDATES;
use super::workflow::{SelectedTargets, approve_operation, resolve_selected};
use super::{Family, Selection, SelectionError, Specification, Target};
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

    pub(crate) fn require(&self, targets: &[super::SelectedAddress]) -> Result<(), E> {
        if targets.is_empty() {
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
pub(crate) fn admit_operation<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, crate::execution::Failure) -> E,
    target: &Target,
    family: FamilyGate<E>,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), E>
where
    A: Authorizer + ResolveTarget,
    Plan: FnOnce(&SelectedTargets) -> Result<P, E>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, E>,
{
    let selected = resolve_selected(authorizer, target, family.family(), deadline, gates)?;
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

/// [`admit_operation`] over a declared [`Selection`].
pub(crate) fn admit_selection<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, crate::execution::Failure) -> E,
    targets: DeclaredTargets<'_, E>,
    invalid: impl Fn(SelectionError) -> E,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), E>
where
    A: Authorizer + ResolveTarget,
    Plan: FnOnce(&SelectedTargets) -> Result<P, E>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, E>,
{
    let family = targets.family;
    let selected = resolve_selection(authorizer, targets, deadline, gates, invalid)?;
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

fn admit_selected<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, crate::execution::Failure) -> E,
    family: FamilyGate<E>,
    selected: SelectedTargets,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), E>
where
    A: Authorizer + ResolveTarget,
    Plan: FnOnce(&SelectedTargets) -> Result<P, E>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, E>,
{
    family.require(&selected.targets)?;
    let plan = plan(&selected)?;
    let operation = operation(&plan)?;
    approve_operation(authorizer, operation, deadline, gates)?;
    Ok((selected, plan))
}

/// Admits the operation from an exact target list the caller already
/// resolved: every entry is re-authorized on its own through
/// [`resolve_selected`], while the original declaration still validates and
/// gates exclusions, family, and `max_targets` for the reported selection.
/// No hostname reaches this path; the workflow validates the list first.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_resolved_selection<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, crate::execution::Failure) -> E,
    targets: DeclaredTargets<'_, E>,
    resolved: &[Target],
    invalid: impl Fn(SelectionError) -> E,
    plan: Plan,
    operation: Build,
) -> Result<(SelectedTargets, P), E>
where
    A: Authorizer + ResolveTarget,
    Plan: FnOnce(&SelectedTargets) -> Result<P, E>,
    Build: for<'a> FnOnce(&'a P) -> Result<Operation<'a>, E>,
{
    let DeclaredTargets {
        selection,
        family,
        max_targets,
    } = targets;
    selection.validate().map_err(&invalid)?;
    if resolved.len() > MAX_CANDIDATES {
        return Err(invalid(SelectionError::Limit {
            field: "target_candidates",
            limit: MAX_CANDIDATES,
        }));
    }
    let family_kind = family.family();
    let enforce = || {
        deadline
            .enforce()
            .map_err(|source| (gates)(0_u64, crate::execution::Failure::Interrupted(source)))
    };
    let mut selected = Vec::new();
    let mut seen = HashSet::<(IpAddr, Option<InterfaceId>)>::new();
    for target in resolved {
        enforce()?;
        let address = match target {
            Target::Address(address) => *address,
            Target::ScopedAddress(scoped) => IpAddr::V6(scoped.address()),
            Target::Hostname(_) => {
                return Err(invalid(SelectionError::Network {
                    value: target.to_string(),
                }));
            }
        };
        if selection.excludes(address) || !family_kind.accepts(address) {
            continue;
        }
        let authorized = resolve_selected(authorizer, target, family_kind, deadline, gates)?;
        for record in authorized.targets {
            enforce()?;
            if selection.excludes(record.address) {
                continue;
            }
            if seen.insert(record.key()) {
                if selected.len() >= max_targets {
                    return Err(invalid(SelectionError::Limit {
                        field: "max_targets",
                        limit: max_targets,
                    }));
                }
                selected.push(record);
            }
        }
    }
    let selected = SelectedTargets {
        declared: selection.to_string(),
        targets: selected,
        declarations: Vec::new(),
        duplicates: Vec::new(),
    };
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

pub(crate) fn resolve_selection<A, E>(
    authorizer: &mut A,
    targets: DeclaredTargets<'_, E>,
    deadline: &Deadline,
    gates: fn(u64, crate::execution::Failure) -> E,
    invalid: impl Fn(SelectionError) -> E,
) -> Result<SelectedTargets, E>
where
    A: Authorizer + ResolveTarget,
{
    let DeclaredTargets {
        selection,
        family,
        max_targets,
    } = targets;
    // Bounds the declaration count, so every index below fits a `u32`.
    selection.validate().map_err(&invalid)?;
    let family = family.family();
    let enforce = || {
        deadline
            .enforce()
            .map_err(|source| (gates)(0_u64, crate::execution::Failure::Interrupted(source)))
    };
    let mut selected = Vec::new();
    let mut origins = Origins::default();
    let mut duplicates = Vec::new();
    let mut seen: HashMap<(IpAddr, Option<InterfaceId>), usize> = HashMap::new();
    // Targets each distinct specification produced, so a repeated declaration
    // links to them without expanding or authorizing again.
    let mut admitted: HashMap<&Specification, BTreeSet<usize>> = HashMap::new();
    let mut candidates = 0usize;
    for (index, specification) in selection.include.iter().enumerate() {
        enforce()?;
        let index = index as u32;
        if let Some(produced) = admitted.get(specification) {
            duplicates.push(index);
            for &target in produced {
                enforce()?;
                origins.link(target, index).map_err(&invalid)?;
            }
            continue;
        }
        let mut produced = BTreeSet::new();
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
            enforce()?;
            candidates = candidates
                .checked_add(1)
                .filter(|count| *count <= MAX_CANDIDATES)
                .ok_or_else(|| {
                    invalid(SelectionError::Limit {
                        field: "target_candidates",
                        limit: MAX_CANDIDATES,
                    })
                })?;
            let numeric = match &target {
                Target::Address(address) => Some(*address),
                Target::ScopedAddress(scoped) => Some(IpAddr::V6(scoped.address())),
                Target::Hostname(_) => None,
            };
            if let Some(address) = numeric {
                if selection.excludes(address) || !family.accepts(address) {
                    continue;
                }
                // An unscoped address already selected merges without
                // authorizing again; a scoped one must resolve its zone first.
                if matches!(target, Target::Address(_))
                    && let Some(&known) = seen.get(&(address, None))
                {
                    if produced.insert(known) {
                        origins.link(known, index).map_err(&invalid)?;
                    }
                    continue;
                }
            }
            let resolved = resolve_selected(authorizer, &target, family, deadline, gates)?;
            for record in resolved.targets {
                enforce()?;
                if selection.excludes(record.address) {
                    continue;
                }
                let target = match seen.entry(record.key()) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        if selected.len() >= max_targets {
                            return Err(invalid(SelectionError::Limit {
                                field: "max_targets",
                                limit: max_targets,
                            }));
                        }
                        selected.push(record);
                        origins.declarations.push(Vec::new());
                        *entry.insert(selected.len() - 1)
                    }
                };
                if produced.insert(target) {
                    origins.link(target, index).map_err(&invalid)?;
                }
            }
        }
        admitted.insert(specification, produced);
    }
    Ok(SelectedTargets {
        declared: selection.to_string(),
        targets: selected,
        declarations: origins.declarations,
        duplicates,
    })
}

/// Declaration indices for each selected target, with one bound on the links
/// across the whole selection.
#[derive(Default)]
struct Origins {
    declarations: Vec<Vec<u32>>,
    links: usize,
}

impl Origins {
    fn link(&mut self, target: usize, declaration: u32) -> Result<(), SelectionError> {
        self.links = self
            .links
            .checked_add(1)
            .filter(|count| *count <= MAX_CANDIDATES)
            .ok_or(SelectionError::Limit {
                field: "target_origins",
                limit: MAX_CANDIDATES,
            })?;
        self.declarations[target].push(declaration);
        Ok(())
    }
}
