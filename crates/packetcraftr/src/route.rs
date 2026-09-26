// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route planning: the passive choice of route, source address, and link for
//! one packet, and its materialization into a sendable route.
//!
//! [`plan`] asks a `packetcraftr_netio::route::Provider` for the route and
//! checks its answer against the packet and the caller's [`Options`]; it
//! performs no discovery, capture, or transmission. The client then
//! materializes an admitted plan into a [`Materialized`] route, running any
//! neighbor resolution the plan still needs.

mod cache;
mod error;
mod intent;
mod materialize;
mod model;
mod planner;

pub(crate) use cache::CachedProvider;
pub use error::Error;
pub use materialize::Materialized;
pub(crate) use materialize::materialize;
pub use model::{MAX_VLAN_TAGS, Options, Plan};
pub use planner::plan;
