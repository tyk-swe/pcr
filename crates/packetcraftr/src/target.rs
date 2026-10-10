// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod admission;
mod model;
pub mod plan;
mod selection;
mod workflow;

pub(crate) use admission::{
    DeclaredTargets, FamilyGate, admit_operation, admit_resolved_selection, admit_selection,
};
#[cfg(test)]
pub(crate) use model::resolve_zone_from;
pub use model::{
    Authorized, Error, Family, Hostname, ResolvedZone, Resolver, ScopedAddress, SelectedAddress,
    SystemResolver, Target, Zone, requires_scope,
};
pub(crate) use model::{ResolveTarget, distinct_addresses, valid_zone_interface};
pub(crate) use selection::MAX_CANDIDATES;
pub use selection::{Network, Selection, SelectionError, Specification};
pub(crate) use workflow::{approve_operation, resolve_selected, wire_limits};
