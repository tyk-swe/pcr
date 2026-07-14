// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

#![forbid(unsafe_code)]

mod cache;
mod options;
mod provider;
#[cfg(test)]
mod tests;
mod wire;

pub use super::route::models::{
    NeighborRequest as Request, NeighborResolution as Resolution, NeighborVlanKind as VlanKind,
    NeighborVlanTag as VlanTag,
};
pub use super::route::planner::{NeighborError as Error, NeighborResolver as Resolver};
pub use options::NeighborResolutionOptions as Options;
pub use provider::{
    ActiveNeighborResolver as ActiveResolver, SystemNeighborResolver as SystemResolver,
};
