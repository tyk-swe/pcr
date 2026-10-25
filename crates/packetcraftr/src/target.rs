// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live targets: addresses, scoped addresses, and hostnames, and the declared
//! selections that expand to them.
//!
//! The model and selection types sit below client admission. [`plan`] is a
//! workflow of its own: it previews what a selection admits without sending
//! traffic.

mod model;
pub mod plan;
mod resolver;
mod selection;

pub use model::{
    Error, Family, Hostname, ResolvedZone, ScopedAddress, SelectedAddress, Target, Zone,
    requires_scope,
};
pub use resolver::{Authorized, BlockingResolver, Resolver, SystemResolver};
pub(crate) use resolver::{ResolveTarget, distinct_addresses, valid_zone_interface};
pub(crate) use selection::MAX_CANDIDATES;
pub use selection::{Network, Selection, SelectionError, Specification};
