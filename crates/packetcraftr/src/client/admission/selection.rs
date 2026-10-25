// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Resolving and authorizing a declared target selection for one operation.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface::Id as InterfaceId;

use super::approval::{SelectedTargets, approve_operation, resolve_selected};
use crate::error::Failure;
use crate::policy::{Authorizer, Operation};
use crate::target::{
    Family, MAX_CANDIDATES, ResolveTarget, SelectedAddress, Selection, SelectionError,
    Specification, Target,
};

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

    pub(crate) fn require(&self, targets: &[SelectedAddress]) -> Result<(), E> {
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
    /// An exact target list the caller already resolved for this
    /// declaration. Each entry is re-authorized on its own through
    /// [`resolve_selected`] instead of expanding the declaration, which still
    /// validates and gates exclusions, family, and `max_targets` for the
    /// reported selection. No hostname may appear here; the workflow
    /// validates the list first.
    pub(crate) resolved: Option<&'a [Target]>,
}

/// Admits one declared target for a live operation: authorized resolution,
/// the empty/family gate, the workflow's budget plan over the admitted
/// addresses, then [`approve_operation`].
pub(crate) fn admit_operation<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
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

/// [`admit_operation`] over a declared [`Selection`], or over the exact
/// targets already resolved for it.
pub(crate) fn admit_selection<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
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
    let selected = match targets.resolved {
        Some(resolved) => resolve_exact(authorizer, targets, resolved, deadline, gates, invalid)?,
        None => resolve_selection(authorizer, targets, deadline, gates, invalid)?,
    };
    admit_selected(
        authorizer, deadline, gates, family, selected, plan, operation,
    )
}

fn admit_selected<A, E, P, Plan, Build>(
    authorizer: &mut A,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
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

/// The selection for [`DeclaredTargets::resolved`]: every exact entry
/// re-authorized in order, deduplicated, and gated by the declaration.
fn resolve_exact<A, E>(
    authorizer: &mut A,
    targets: DeclaredTargets<'_, E>,
    resolved: &[Target],
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
    invalid: impl Fn(SelectionError) -> E,
) -> Result<SelectedTargets, E>
where
    A: Authorizer + ResolveTarget,
{
    let DeclaredTargets {
        selection,
        family,
        max_targets,
        ..
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
            .map_err(|source| (gates)(0_u64, Failure::Interrupted(source)))
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
    Ok(SelectedTargets {
        declared: selection.to_string(),
        targets: selected,
        declarations: Vec::new(),
        duplicates: Vec::new(),
    })
}

fn resolve_selection<A, E>(
    authorizer: &mut A,
    targets: DeclaredTargets<'_, E>,
    deadline: &Deadline,
    gates: fn(u64, Failure) -> E,
    invalid: impl Fn(SelectionError) -> E,
) -> Result<SelectedTargets, E>
where
    A: Authorizer + ResolveTarget,
{
    let DeclaredTargets {
        selection,
        family,
        max_targets,
        ..
    } = targets;
    // Bounds the declaration count, so every index below fits a `u32`.
    selection.validate().map_err(&invalid)?;
    let family = family.family();
    let enforce = || {
        deadline
            .enforce()
            .map_err(|source| (gates)(0_u64, Failure::Interrupted(source)))
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
