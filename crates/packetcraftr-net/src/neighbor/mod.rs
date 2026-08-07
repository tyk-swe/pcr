// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.

#![forbid(unsafe_code)]

mod cache;
mod error;
mod evidence;
mod options;
mod provider;
mod wire;

pub use super::route::materialize::{NeighborError as Error, NeighborResolver as Resolver};
pub use super::route::models::{
    NeighborRequest as Request, NeighborResolution as Resolution, NeighborVlanKind as VlanKind,
    NeighborVlanTag as VlanTag,
};
pub use options::NeighborResolutionOptions as Options;
pub use provider::{
    ActiveNeighborResolver as ActiveResolver, SystemNeighborResolver as SystemResolver,
};
