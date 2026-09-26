// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live target resolution and operation admission.

mod admission;
mod model;
mod selection;
mod workflow;

pub(crate) use admission::{DeclaredTargets, FamilyGate, admit_operation, admit_selection};
pub use model::{Authorized, Error, Family, Hostname, Resolver, SystemResolver, Target};
pub use selection::{Network, Selection, SelectionError, Specification};
pub(crate) use workflow::{approve_operation, resolve_selected, wire_limits};
