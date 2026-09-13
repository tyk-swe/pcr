// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live target resolution.

mod model;
mod selection;
mod workflow;

pub use model::{Authorized, Error, Family, Hostname, Resolver, SystemResolver, Target};
pub use selection::{Network, Selection, SelectionError, Specification};
pub(crate) use workflow::{GateErrors, approve_operation, budgeted, resolve_selected};

pub(crate) use selection::MAX_CANDIDATES;
